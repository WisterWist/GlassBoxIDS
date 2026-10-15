"""
tutor.py - AI Security Tutor Engine for Glass-Box IDS.

Integrates with the Gemini API to provide interactive pedagogical breakdowns
of detected network anomalies, protocol mechanics, and remediation instructions
(Windows Defender Firewall / PowerShell, iptables, Snort signatures) for students.
Queries execute asynchronously in daemon threads to keep the GUI responsive.
"""

import json
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, Optional
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

DEFAULT_SYSTEM_INSTRUCTION = (
    "You are an encouraging, expert cybersecurity tutor embedded inside the Glass-Box IDS "
    "educational software. Your purpose is to demystify network attacks, explain networking "
    "protocols (TCP/UDP/ICMP), and provide defensive remediation (such as Windows Defender "
    "Firewall / PowerShell rules, iptables, and Snort signatures) tailored to undergraduate students."
)


class SecurityTutor:
    """
    AI Security Tutor client interfacing with Gemini API via Google GenAI SDK
    or zero-dependency raw HTTPS fallback. Manages API key persistence, automatic
    model migration, and non-blocking asynchronous query execution with retry backoff.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        model: str = "gemini-3.6-flash",
    ) -> None:
        """
        Initialize the SecurityTutor.

        :param config_path: Path to local config.json file (defaults to project root).
        :param model: Gemini model identifier (default: gemini-3.6-flash).
        """
        if config_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_dir, "config.json")

        self.config_path: str = config_path
        self.model: str = model
        self.api_key: str = ""
        self.system_instruction: str = DEFAULT_SYSTEM_INSTRUCTION
        self._lock: threading.Lock = threading.Lock()

        # Load persisted configuration and migrate deprecated models if needed
        self._load_config()

    def _load_config(self) -> None:
        """Load API key and settings from local config.json, auto-migrating deprecated models."""
        needs_migration = False
        with self._lock:
            if os.path.exists(self.config_path):
                try:
                    with open(self.config_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.api_key = data.get("api_key", "").strip()
                        loaded_model = data.get("model", self.model).strip()

                        # Auto-migrate deprecated models (e.g. 2.5-flash or 1.5-flash) to gemini-3.6-flash
                        if loaded_model in (
                            "gemini-2.5-flash",
                            "gemini-1.5-flash",
                            "models/gemini-2.5-flash",
                            "models/gemini-1.5-flash",
                        ):
                            self.model = "gemini-3.6-flash"
                            needs_migration = True
                        else:
                            self.model = loaded_model
                except Exception as exc:
                    logger.warning("Failed to read %s: %s", self.config_path, exc)

        if needs_migration:
            self._save_config()
            logger.info("Migrated deprecated model in %s to %s", self.config_path, self.model)

    def _save_config(self) -> bool:
        """Persist current settings to config.json."""
        with self._lock:
            try:
                data = {
                    "api_key": self.api_key,
                    "model": self.model,
                }
                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                return True
            except Exception as exc:
                logger.error("Failed to write %s: %s", self.config_path, exc)
                return False

    def set_api_key(self, api_key: str) -> bool:
        """
        Update and persist the Gemini API key.

        :param api_key: New Gemini API key string.
        :return: True if successfully persisted, False otherwise.
        """
        clean_key = api_key.strip()
        self.api_key = clean_key
        return self._save_config()

    def get_api_key(self) -> str:
        """Return the currently configured Gemini API key."""
        with self._lock:
            return self.api_key

    def is_configured(self) -> bool:
        """Return True if an API key is currently configured."""
        with self._lock:
            return bool(self.api_key)

    def _format_prompt(self, user_prompt: str, context: Optional[Dict[str, Any]]) -> str:
        """Combine user question with current attack context if present."""
        if not context:
            return user_prompt

        context_lines = []
        if "attack_type" in context:
            context_lines.append(f"- Detected Threat: {context['attack_type']}")
        if "attacker_ip" in context:
            context_lines.append(f"- Attacker Source IP: {context['attacker_ip']}")
        if "port" in context:
            context_lines.append(f"- Target Destination Port: {context['port']}")
        if "packet_count" in context:
            context_lines.append(f"- Frequency / Packet Count: {context['packet_count']}")
        if "explanation" in context:
            context_lines.append(f"- IDS Diagnostic: {context['explanation']}")

        if context_lines:
            context_block = (
                "[Current IDS Alert Telemetry Context]:\n"
                + "\n".join(context_lines)
                + "\n\n[Student Inquiry]:\n"
            )
            return context_block + user_prompt

        return user_prompt

    def _query_api(self, formatted_prompt: str) -> str:
        """
        Execute API call using Google GenAI SDK if installed, or fallback to
        direct REST HTTPS query using urllib with automatic retry backoff.
        """
        primary_model = self.model.replace("models/", "")

        # 1. Attempt official google-genai SDK if available
        try:
            from google import genai  # type: ignore

            client = genai.Client(api_key=self.api_key)
            response = client.models.generate_content(
                model=primary_model,
                contents=formatted_prompt,
            )
            if hasattr(response, "text") and response.text:
                return response.text
        except ImportError:
            pass
        except Exception as sdk_exc:
            logger.info("google-genai SDK call failed, trying REST HTTPS: %s", sdk_exc)

        # 2. Candidate model fallback list
        fallback_list = ["gemini-3.6-flash", "gemini-3.8-flash", "gemini-flash-latest"]
        models_to_try = [primary_model]
        for m in fallback_list:
            if m not in models_to_try:
                models_to_try.append(m)

        last_error = ""

        for target_model in models_to_try:
            model_name = target_model.replace("models/", "")
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.api_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": formatted_prompt}]}],
                "generationConfig": {
                    "temperature": 0.7,
                    "maxOutputTokens": 4096,
                    "thinkingConfig": {
                        "thinkingBudget": 0,
                    },
                },
            }

            req_data = json.dumps(payload).encode("utf-8")
            max_attempts = 3

            for attempt in range(max_attempts):
                req = urllib.request.Request(
                    url,
                    data=req_data,
                    headers=headers,
                    method="POST",
                )

                try:
                    with urllib.request.urlopen(req, timeout=25.0) as response:
                        body = json.loads(response.read().decode("utf-8"))
                        candidates = body.get("candidates", [])
                        if candidates:
                            candidate = candidates[0]
                            text_parts = []
                            for part in candidate.get("content", {}).get("parts", []):
                                if not part.get("thought", False) and "text" in part:
                                    text_parts.append(part["text"])
                            tutor_reply = "".join(text_parts).strip()
                            if tutor_reply:
                                return tutor_reply

                            finish_reason = candidate.get("finishReason", "")
                            if finish_reason == "MAX_TOKENS":
                                return (
                                    "Output token limit reached before the response completed. "
                                    "Please ask a more specific question or request a shorter explanation."
                                )
                            if finish_reason:
                                return f"Tutor response was terminated (Reason: {finish_reason})."
                        return "Tutor provided an empty response."
                except urllib.error.HTTPError as e:
                    err_body = e.read().decode("utf-8")
                    print(
                        f"[Gemini API HTTPError {e.code} for model '{model_name}' "
                        f"(Attempt {attempt + 1}/{max_attempts})]:\n{err_body}"
                    )
                    last_error = f"HTTP {e.code}: {e.reason}"

                    # If model returns 404, immediately skip retries and try next model
                    if e.code == 404:
                        break

                    # If 503 (high demand) or 429 (rate limit), retry with exponential backoff
                    if e.code in (503, 429):
                        if attempt < max_attempts - 1:
                            backoff_sec = 1.5 * (attempt + 1)
                            print(f"Retrying model '{model_name}' in {backoff_sec:.1f}s due to HTTP {e.code}...")
                            time.sleep(backoff_sec)
                            continue
                        else:
                            # Attempts exhausted for this model, fall through to next model
                            break

                    try:
                        err_json = json.loads(err_body)
                        err_msg = err_json.get("error", {}).get("message", last_error)
                        return f"API Error ({err_msg})"
                    except Exception:
                        return f"API Error ({err_body or last_error})"

                except Exception as net_err:
                    last_error = str(net_err)
                    print(
                        f"[Gemini API Network Error for model '{model_name}' "
                        f"(Attempt {attempt + 1}/{max_attempts})]: {net_err}"
                    )
                    if attempt < max_attempts - 1:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                    break

        return f"Unable to reach Gemini API: {last_error}"

    def ask_async(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        callback: Optional[Callable[[str, bool], None]] = None,
    ) -> None:
        """
        Submit a query to the AI Security Tutor on a background daemon thread.
        Triggers callback(response_text, is_success) upon completion.

        :param prompt: Student question or topic prompt.
        :param context: Optional dictionary containing recent alert telemetry.
        :param callback: Callable invoked with (response_text, is_success).
        """
        def _worker() -> None:
            if not self.is_configured():
                err_msg = (
                    "Gemini API key is not configured.\n"
                    "Please paste your API key in the top configuration bar and click 'Save Key'.\n"
                    "(You can obtain a free API key at https://aistudio.google.com)"
                )
                if callback:
                    callback(err_msg, False)
                return

            try:
                user_content = self._format_prompt(prompt, context)
                formatted_prompt = f"{self.system_instruction}\n\n{user_content}"
                response_text = self._query_api(formatted_prompt)
                is_success = not response_text.startswith("Unable to reach") and not response_text.startswith("API Error")
                if callback:
                    callback(response_text, is_success)
            except Exception as exc:
                logger.error("Unexpected error in SecurityTutor query: %s", exc)
                if callback:
                    callback(f"An unexpected error occurred: {exc}", False)

        thread = threading.Thread(
            target=_worker,
            name="GlassBox-AITutorThread",
            daemon=True,
        )
        thread.start()
