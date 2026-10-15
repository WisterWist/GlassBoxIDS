"""
ui.py - Multi-Page CustomTkinter Dashboard for Glass-Box IDS.

Features:
- Multi-view navigation (Live Monitor, Noise & Exclusions, Rule Tuning, AI Security Tutor).
- Real-time traffic feed with syntax highlighting (green for normal, bold red for alerts).
- Educational Threat Inspector for pedagogical breakdowns.
- Contextual AI Threat Escalation ("✨ Ask AI Tutor About This Alert").
- Embedded AI Security Tutor powered by Gemini API with quick-action pills and persistent config.
- Dedicated Suppressed Noise view for filtered multicast, broadcast, and whitelisted packets.
- Interactive IP Whitelist management card.
- Live Rule Tuning sliders and enterprise filter toggles updating ThreatDetector in real time.
- Thread-safe queue polling and non-blocking background sniffing.
"""

import ipaddress
import os
import queue
import time
from typing import Optional, Tuple

import customtkinter as ctk
from PIL import Image

from detector import ThreatDetector
from sniffer import NetworkSniffer
from tutor import SecurityTutor

# Initialize appearance settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class GlassBoxUI(ctk.CTk):
    """
    Multi-Page Application Dashboard for the Glass-Box Intrusion Detection System.
    Provides real-time packet telemetry, transparent noise suppression views,
    interactive whitelist exclusions, on-the-fly rule tuning, and an embedded
    AI Security Tutor powered by Gemini.
    """

    def __init__(
        self,
        packet_queue: "queue.Queue[Tuple[str, str, Optional[str]]]",
        sniffer: NetworkSniffer,
        detector: Optional[ThreatDetector] = None,
        tutor: Optional[SecurityTutor] = None,
    ) -> None:
        """
        Initialize the GlassBoxUI dashboard.

        :param packet_queue: Thread-safe queue delivering (status, log, explanation) tuples.
        :param sniffer: Instance of NetworkSniffer controlled by Start/Stop buttons.
        :param detector: Instance of ThreatDetector for live rule adjustments.
        :param tutor: Instance of SecurityTutor for conversational AI threat analysis.
        """
        super().__init__()

        self.packet_queue = packet_queue
        self.sniffer = sniffer
        self.detector = detector if detector is not None else sniffer.detector
        self.tutor = tutor if tutor is not None else SecurityTutor()

        # Window Configuration
        self.title("Glass-Box IDS - Multi-View Educational Security Dashboard")
        self.geometry("1050x720")
        self.minsize(980, 640)

        # Internal Telemetry Metrics & Alert Context
        self.total_packets: int = 0
        self.total_alerts: int = 0
        self.total_suppressed: int = 0
        self._is_open: bool = True
        self._poll_after_id: Optional[str] = None
        self._current_view: str = "live"
        self.latest_threat_context: Optional[dict] = None

        # Construct Master Layout
        self._setup_master_layout()
        self._setup_sidebar()
        self._setup_views()
        self._setup_text_tags()

        # Display default view ("Live Monitor")
        self._show_view("live")

        # Intercept window close event for graceful cleanup
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Start periodic queue polling
        self._poll_queue()

    def _setup_master_layout(self) -> None:
        """Configure master grid weights."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0, minsize=260)  # Left Sidebar
        self.grid_columnconfigure(1, weight=1)              # Main Content Area

    def _setup_sidebar(self) -> None:
        """Construct sidebar with title, logo, navigation, capture controls, and telemetry cards."""
        self.sidebar_frame = ctk.CTkFrame(self, corner_radius=10)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)

        # 1. Branding Header with Logo Icon
        self.header_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.header_frame.pack(pady=(16, 2), padx=16, anchor="w", fill="x")

        # Load logo icon (logo.webp or glass_block.webp)
        self.logo_image = None
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            logo_path = os.path.join(base_dir, "logo.webp")
            if not os.path.exists(logo_path):
                logo_path = os.path.join(base_dir, "glass_block.webp")

            if os.path.exists(logo_path):
                pil_img = Image.open(logo_path)
                self.logo_image = ctk.CTkImage(
                    light_image=pil_img, dark_image=pil_img, size=(36, 36)
                )
        except Exception:
            self.logo_image = None

        if self.logo_image is not None:
            self.logo_icon_label = ctk.CTkLabel(
                self.header_frame,
                text="",
                image=self.logo_image,
            )
            self.logo_icon_label.pack(side="left", padx=(0, 10))

        self.logo_label = ctk.CTkLabel(
            self.header_frame,
            text="Glass-Box IDS",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        self.logo_label.pack(side="left", anchor="w")

        self.subtitle_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Explainable Security Dashboard",
            font=ctk.CTkFont(size=11),
            text_color="#95a5a6",
        )
        self.subtitle_label.pack(pady=(0, 14), padx=16, anchor="w")

        # 2. Navigation Section
        self.nav_section_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="NAVIGATION",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#7f8c8d",
        )
        self.nav_section_label.pack(pady=(4, 6), padx=16, anchor="w")

        self.nav_live_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="📡  Live Monitor",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
            height=36,
            command=lambda: self._show_view("live"),
        )
        self.nav_live_btn.pack(pady=3, padx=14, fill="x")

        self.nav_noise_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🛡️  Noise & Exclusions",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
            height=36,
            command=lambda: self._show_view("noise"),
        )
        self.nav_noise_btn.pack(pady=3, padx=14, fill="x")

        self.nav_tuning_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="⚙️  Rule Tuning",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
            height=36,
            command=lambda: self._show_view("tuning"),
        )
        self.nav_tuning_btn.pack(pady=3, padx=14, fill="x")

        self.nav_tutor_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="🤖  AI Security Tutor",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
            height=36,
            command=lambda: self._show_view("tutor"),
        )
        self.nav_tutor_btn.pack(pady=3, padx=14, fill="x")

        # 3. Packet Capture Controls
        self.control_section_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="CAPTURE CONTROLS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#7f8c8d",
        )
        self.control_section_label.pack(pady=(16, 6), padx=16, anchor="w")

        self.start_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="▶ Start Monitoring",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60",
            text_color="#ffffff",
            height=36,
            command=self._start_monitoring,
        )
        self.start_btn.pack(pady=4, padx=14, fill="x")

        self.stop_btn = ctk.CTkButton(
            self.sidebar_frame,
            text="⏹ Stop Monitoring",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#e74c3c",
            hover_color="#c0392b",
            text_color="#ffffff",
            height=36,
            state="disabled",
            command=self._stop_monitoring,
        )
        self.stop_btn.pack(pady=4, padx=14, fill="x")

        # Status Badge
        self.status_badge = ctk.CTkLabel(
            self.sidebar_frame,
            text="● Status: IDLE",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#95a5a6",
        )
        self.status_badge.pack(pady=(10, 12), padx=16, anchor="w")

        # 4. Telemetry Card
        self.metrics_frame = ctk.CTkFrame(self.sidebar_frame, corner_radius=8, fg_color="#1e2227")
        self.metrics_frame.pack(pady=4, padx=14, fill="x")

        self.metrics_title = ctk.CTkLabel(
            self.metrics_frame,
            text="TELEMETRY METRICS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#7f8c8d",
        )
        self.metrics_title.pack(pady=(8, 4), padx=12, anchor="w")

        self.total_packets_label = ctk.CTkLabel(
            self.metrics_frame,
            text="Total Packets: 0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#ecf0f1",
        )
        self.total_packets_label.pack(pady=2, padx=12, anchor="w")

        self.total_alerts_label = ctk.CTkLabel(
            self.metrics_frame,
            text="Alerts: 0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#ff4d4d",
        )
        self.total_alerts_label.pack(pady=2, padx=12, anchor="w")

        self.total_suppressed_label = ctk.CTkLabel(
            self.metrics_frame,
            text="Suppressed: 0",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f39c12",
        )
        self.total_suppressed_label.pack(pady=(2, 10), padx=12, anchor="w")

    def _setup_views(self) -> None:
        """Create main view containers for multi-page navigation."""
        self.main_container = ctk.CTkFrame(self, corner_radius=10)
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        # Construct each page view inside the container
        self._build_live_monitor_view()
        self._build_noise_exclusions_view()
        self._build_rule_tuning_view()
        self._build_ai_tutor_view()

    def _build_live_monitor_view(self) -> None:
        """View 1: Live Network Traffic Feed and Educational Threat Inspector."""
        self.view_live = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.view_live.grid_rowconfigure(0, weight=0)  # Traffic Header
        self.view_live.grid_rowconfigure(1, weight=3)  # Traffic Textbox
        self.view_live.grid_rowconfigure(2, weight=0)  # Inspector Header
        self.view_live.grid_rowconfigure(3, weight=2)  # Inspector Textbox
        self.view_live.grid_columnconfigure(0, weight=1)

        # Traffic Feed Header Frame
        self.traffic_header_frame = ctk.CTkFrame(self.view_live, fg_color="transparent")
        self.traffic_header_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))

        self.traffic_header = ctk.CTkLabel(
            self.traffic_header_frame,
            text="📡 Live Network Traffic Feed (Green: Safe | Red: Threat Alert)",
            font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.traffic_header.pack(side="left")

        self.clear_traffic_btn = ctk.CTkButton(
            self.traffic_header_frame,
            text="Clear Feed",
            width=90,
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#34495e",
            hover_color="#2c3e50",
            command=self._clear_traffic_feed,
        )
        self.clear_traffic_btn.pack(side="right")

        self.traffic_box = ctk.CTkTextbox(
            self.view_live,
            font=("Consolas", 10),
            wrap="none",
            corner_radius=8,
        )
        self.traffic_box.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 10))

        # Threat Inspector Header Frame
        self.inspector_header_frame = ctk.CTkFrame(self.view_live, fg_color="transparent")
        self.inspector_header_frame.grid(row=2, column=0, sticky="ew", padx=14, pady=(6, 4))

        self.inspector_header = ctk.CTkLabel(
            self.inspector_header_frame,
            text="🔍 Educational Threat Inspector (Glass-Box Deep Dive)",
            font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.inspector_header.pack(side="left")

        # "Clear Inspector" Button
        self.clear_inspector_btn = ctk.CTkButton(
            self.inspector_header_frame,
            text="Clear Inspector",
            width=110,
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#34495e",
            hover_color="#2c3e50",
            command=self._clear_inspector,
        )
        self.clear_inspector_btn.pack(side="right", padx=(6, 0))

        # "✨ Ask AI Tutor About This Alert" Button
        self.ask_tutor_alert_btn = ctk.CTkButton(
            self.inspector_header_frame,
            text="✨ Ask AI Tutor About This Alert",
            width=180,
            height=24,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#8e44ad",
            hover_color="#7d3c98",
            text_color="#ffffff",
            command=self._on_ask_tutor_about_alert,
        )
        self.ask_tutor_alert_btn.pack(side="right", padx=(6, 0))

        self.inspector_box = ctk.CTkTextbox(
            self.view_live,
            font=("Consolas", 10),
            wrap="word",
            corner_radius=8,
        )
        self.inspector_box.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 14))

        welcome_text = (
            "System initialized. Ready for packet inspection.\n"
            "Pedagogical breakdowns detailing TCP 3-way handshakes, ICMP ping storms, "
            "and UDP sweep mechanics will appear here when security anomalies trigger.\n\n"
            "Tip: Click '✨ Ask AI Tutor About This Alert' to escalate any detected threat "
            "directly to the Gemini AI Security Tutor for defense steps and firewall commands!\n"
        )
        self.inspector_box.insert("end", welcome_text)

    def _build_noise_exclusions_view(self) -> None:
        """View 2: Dedicated Suppressed Noise Feed & IP Whitelist Management Card."""
        self.view_noise = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.view_noise.grid_rowconfigure(0, weight=0)  # Header
        self.view_noise.grid_rowconfigure(1, weight=3)  # Suppressed Feed Textbox
        self.view_noise.grid_rowconfigure(2, weight=0)  # Whitelist Card
        self.view_noise.grid_columnconfigure(0, weight=1)

        # Noise Header Frame
        self.noise_header_frame = ctk.CTkFrame(self.view_noise, fg_color="transparent")
        self.noise_header_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))

        self.noise_header = ctk.CTkLabel(
            self.noise_header_frame,
            text="🛡️ Filtered Enterprise Noise Feed (Amber: Multicast / Broadcast / Whitelisted)",
            font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.noise_header.pack(side="left")

        self.clear_noise_btn = ctk.CTkButton(
            self.noise_header_frame,
            text="Clear Feed",
            width=90,
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#34495e",
            hover_color="#2c3e50",
            command=self._clear_noise_feed,
        )
        self.clear_noise_btn.pack(side="right")

        # Suppressed Feed Textbox
        self.suppressed_box = ctk.CTkTextbox(
            self.view_noise,
            font=("Consolas", 10),
            wrap="none",
            corner_radius=8,
        )
        self.suppressed_box.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.noise_box = self.suppressed_box

        # Whitelist Management Card Frame
        self.whitelist_card = ctk.CTkFrame(self.view_noise, corner_radius=8, fg_color="#1e2227")
        self.whitelist_card.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 14))

        self.whitelist_title = ctk.CTkLabel(
            self.whitelist_card,
            text="IP EXCLUSION WHITELIST MANAGEMENT",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#ecf0f1",
        )
        self.whitelist_title.pack(pady=(12, 4), padx=14, anchor="w")

        self.whitelist_desc = ctk.CTkLabel(
            self.whitelist_card,
            text="Traffic from or to whitelisted IP addresses is categorized as 'SUPPRESSED' and bypassed from alert triggers.",
            font=ctk.CTkFont(size=11),
            text_color="#95a5a6",
        )
        self.whitelist_desc.pack(pady=(0, 10), padx=14, anchor="w")

        # Input & Button Controls
        self.whitelist_input_frame = ctk.CTkFrame(self.whitelist_card, fg_color="transparent")
        self.whitelist_input_frame.pack(pady=4, padx=14, fill="x")

        self.ip_entry = ctk.CTkEntry(
            self.whitelist_input_frame,
            placeholder_text="Enter IPv4 Address (e.g., 192.168.1.100)",
            font=ctk.CTkFont(size=12),
            height=34,
            width=280,
        )
        self.ip_entry.pack(side="left", padx=(0, 8))

        self.add_ip_btn = ctk.CTkButton(
            self.whitelist_input_frame,
            text="+ Add to Whitelist",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#3498db",
            hover_color="#2980b9",
            height=34,
            command=self._on_add_whitelist,
        )
        self.add_ip_btn.pack(side="left", padx=4)

        self.clear_ip_btn = ctk.CTkButton(
            self.whitelist_input_frame,
            text="Clear Whitelist",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#7f8c8d",
            hover_color="#636e72",
            height=34,
            command=self._on_clear_whitelist,
        )
        self.clear_ip_btn.pack(side="left", padx=4)

        # Active Whitelist Display Label
        self.active_whitelist_label = ctk.CTkLabel(
            self.whitelist_card,
            text="Active Whitelist: (None)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#f39c12",
            wraplength=680,
            justify="left",
        )
        self.active_whitelist_label.pack(pady=(10, 12), padx=14, anchor="w")

    def _build_rule_tuning_view(self) -> None:
        """View 3: Live Interactive Rule Tuning Sliders & Enterprise Filter Toggles."""
        self.view_tuning = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.view_tuning.grid_rowconfigure(0, weight=0)  # Header
        self.view_tuning.grid_rowconfigure(1, weight=1)  # Sliders & Toggles Card
        self.view_tuning.grid_columnconfigure(0, weight=1)

        # Header
        self.tuning_header = ctk.CTkLabel(
            self.view_tuning,
            text="⚙️ Live Rule Tuning & Sensitivity Configuration",
            font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.tuning_header.grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))

        # Main Tuning Card Frame
        self.tuning_card = ctk.CTkScrollableFrame(self.view_tuning, corner_radius=8, fg_color="#1e2227")
        self.tuning_card.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 14))

        card_intro = (
            "Adjust detection sensitivity and enterprise suppression parameters in real time.\n"
            "Modifications apply immediately to the running ThreatDetector engine without restarting."
        )
        self.tuning_card_intro = ctk.CTkLabel(
            self.tuning_card,
            text=card_intro,
            font=ctk.CTkFont(size=11),
            text_color="#95a5a6",
            justify="left",
        )
        self.tuning_card_intro.pack(pady=(8, 16), padx=16, anchor="w")

        # 1. Slider: TCP SYN Threshold
        self.syn_slider_label = ctk.CTkLabel(
            self.tuning_card,
            text=f"TCP SYN Flood / Scan Threshold: {self.detector.tcp_syn_threshold} packets",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#ecf0f1",
        )
        self.syn_slider_label.pack(pady=(6, 2), padx=16, anchor="w")

        self.syn_slider = ctk.CTkSlider(
            self.tuning_card,
            from_=1,
            to=50,
            number_of_steps=49,
            command=self._on_syn_slider_change,
        )
        self.syn_slider.set(self.detector.tcp_syn_threshold)
        self.syn_slider.pack(pady=(2, 14), padx=16, fill="x")

        # 2. Slider: ICMP Ping Flood Threshold
        self.icmp_slider_label = ctk.CTkLabel(
            self.tuning_card,
            text=f"ICMP Echo Request Ping Flood Threshold: {self.detector.icmp_threshold} packets",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#ecf0f1",
        )
        self.icmp_slider_label.pack(pady=(6, 2), padx=16, anchor="w")

        self.icmp_slider = ctk.CTkSlider(
            self.tuning_card,
            from_=1,
            to=50,
            number_of_steps=49,
            command=self._on_icmp_slider_change,
        )
        self.icmp_slider.set(self.detector.icmp_threshold)
        self.icmp_slider.pack(pady=(2, 14), padx=16, fill="x")

        # 3. Slider: UDP Sweep / Flood Threshold
        self.udp_slider_label = ctk.CTkLabel(
            self.tuning_card,
            text=f"UDP Sweep / Flood Threshold: {self.detector.udp_threshold} datagrams",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#ecf0f1",
        )
        self.udp_slider_label.pack(pady=(6, 2), padx=16, anchor="w")

        self.udp_slider = ctk.CTkSlider(
            self.tuning_card,
            from_=1,
            to=100,
            number_of_steps=99,
            command=self._on_udp_slider_change,
        )
        self.udp_slider.set(self.detector.udp_threshold)
        self.udp_slider.pack(pady=(2, 14), padx=16, fill="x")

        # 4. Slider: Sliding Window Duration
        self.window_slider_label = ctk.CTkLabel(
            self.tuning_card,
            text=f"Sliding Frequency Window Duration: {self.detector.window_duration:.1f} seconds",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#ecf0f1",
        )
        self.window_slider_label.pack(pady=(6, 2), padx=16, anchor="w")

        self.window_slider = ctk.CTkSlider(
            self.tuning_card,
            from_=1.0,
            to=10.0,
            number_of_steps=18,
            command=self._on_window_slider_change,
        )
        self.window_slider.set(self.detector.window_duration)
        self.window_slider.pack(pady=(2, 18), padx=16, fill="x")

        # Separator Line
        self.tuning_sep = ctk.CTkFrame(self.tuning_card, height=2, fg_color="#2c3e50")
        self.tuning_sep.pack(pady=8, padx=16, fill="x")

        # 5. Enterprise Filter Toggles
        self.toggles_title = ctk.CTkLabel(
            self.tuning_card,
            text="ENTERPRISE NOISE SUPPRESSION FILTERS (e.g. Eduroam Wi-Fi)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#7f8c8d",
        )
        self.toggles_title.pack(pady=(12, 8), padx=16, anchor="w")

        self.switch_multicast = ctk.CTkSwitch(
            self.tuning_card,
            text="Filter Multicast / mDNS Traffic (224.0.0.0/4, UDP port 5353)",
            font=ctk.CTkFont(size=12),
            command=self._on_multicast_toggle,
        )
        if self.detector.filter_multicast:
            self.switch_multicast.select()
        else:
            self.switch_multicast.deselect()
        self.switch_multicast.pack(pady=6, padx=16, anchor="w")

        self.switch_broadcast = ctk.CTkSwitch(
            self.tuning_card,
            text="Filter Local Broadcast / SSDP Traffic (255.255.255.255, UDP port 1900)",
            font=ctk.CTkFont(size=12),
            command=self._on_broadcast_toggle,
        )
        if self.detector.filter_broadcast:
            self.switch_broadcast.select()
        else:
            self.switch_broadcast.deselect()
        self.switch_broadcast.pack(pady=(6, 16), padx=16, anchor="w")

    def _build_ai_tutor_view(self) -> None:
        """View 4: AI Security Tutor Powered by Gemini API."""
        self.view_tutor = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.view_tutor.grid_rowconfigure(0, weight=0)  # Config Card
        self.view_tutor.grid_rowconfigure(1, weight=1)  # Chat Feed Textbox
        self.view_tutor.grid_rowconfigure(2, weight=0)  # Quick Action Pills
        self.view_tutor.grid_rowconfigure(3, weight=0)  # Bottom Input Bar
        self.view_tutor.grid_columnconfigure(0, weight=1)

        # Top Section: API Configuration Card
        self.api_card = ctk.CTkFrame(self.view_tutor, corner_radius=8, fg_color="#1e2227")
        self.api_card.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))

        self.api_card_header = ctk.CTkFrame(self.api_card, fg_color="transparent")
        self.api_card_header.pack(fill="x", padx=14, pady=(10, 4))

        self.api_title = ctk.CTkLabel(
            self.api_card_header,
            text="GEMINI AI CONFIGURATION",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#ecf0f1",
        )
        self.api_title.pack(side="left")

        self.api_status_badge = ctk.CTkLabel(
            self.api_card_header,
            text="",
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.api_status_badge.pack(side="right")
        self._update_tutor_status_badge()

        self.api_controls_frame = ctk.CTkFrame(self.api_card, fg_color="transparent")
        self.api_controls_frame.pack(fill="x", padx=14, pady=(4, 10))

        self.api_key_entry = ctk.CTkEntry(
            self.api_controls_frame,
            placeholder_text="Enter Gemini API Key (e.g. AIzaSy...)",
            show="*",
            font=ctk.CTkFont(size=12),
            height=34,
        )
        self.api_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        if self.tutor.is_configured():
            self.api_key_entry.insert(0, self.tutor.get_api_key())

        self.save_key_btn = ctk.CTkButton(
            self.api_controls_frame,
            text="Save Key",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60",
            width=90,
            height=34,
            command=self._on_save_api_key,
        )
        self.save_key_btn.pack(side="right")

        # Chat Feed Textbox
        self.tutor_chat_box = ctk.CTkTextbox(
            self.view_tutor,
            font=("Consolas", 10),
            wrap="word",
            corner_radius=8,
        )
        self.tutor_chat_box.grid(row=1, column=0, sticky="nsew", padx=12, pady=(4, 6))

        welcome_tutor = (
            "🤖 Welcome to the Glass-Box AI Security Tutor!\n"
            "I am here to demystify network attacks, explain TCP/UDP/ICMP protocol behavior, "
            "and generate concrete defensive rules (PowerShell commands, iptables, and Snort signatures).\n\n"
            "Ask any question below or click the quick-action pills to investigate recent threats!\n"
            + "=" * 75 + "\n\n"
        )
        self.tutor_chat_box.insert("end", welcome_tutor, "tutor_welcome")

        # Quick-Action Pill Buttons
        self.pills_frame = ctk.CTkFrame(self.view_tutor, fg_color="transparent")
        self.pills_frame.grid(row=2, column=0, sticky="ew", padx=12, pady=(2, 6))

        self.pill_mitigate = ctk.CTkButton(
            self.pills_frame,
            text="🛡️ How to Mitigate",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#2c3e50",
            hover_color="#34495e",
            height=28,
            command=lambda: self._send_tutor_query(
                "How do I mitigate this attack? Provide immediate defense steps and network configurations."
            ),
        )
        self.pill_mitigate.pack(side="left", padx=(0, 6))

        self.pill_eli5 = ctk.CTkButton(
            self.pills_frame,
            text="📖 Explain Like I'm 10",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#2c3e50",
            hover_color="#34495e",
            height=28,
            command=lambda: self._send_tutor_query(
                "Explain this attack and the underlying networking protocol mechanics like I'm 10 years old."
            ),
        )
        self.pill_eli5.pack(side="left", padx=6)

        self.pill_firewall = ctk.CTkButton(
            self.pills_frame,
            text="💻 Windows Firewall Rule",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#2c3e50",
            hover_color="#34495e",
            height=28,
            command=lambda: self._send_tutor_query(
                "Provide the exact Windows Defender Firewall / PowerShell command to block this attack."
            ),
        )
        self.pill_firewall.pack(side="left", padx=6)

        # Bottom Input Bar
        self.input_bar_frame = ctk.CTkFrame(self.view_tutor, fg_color="transparent")
        self.input_bar_frame.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))

        self.tutor_input_entry = ctk.CTkEntry(
            self.input_bar_frame,
            placeholder_text="Ask the AI Tutor anything about network attacks, Wireshark, firewall rules...",
            font=ctk.CTkFont(size=12),
            height=38,
        )
        self.tutor_input_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.tutor_input_entry.bind(
            "<Return>", lambda _event: self._send_tutor_query(self.tutor_input_entry.get())
        )

        self.tutor_send_btn = ctk.CTkButton(
            self.input_bar_frame,
            text="➤ Send",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#3498db",
            hover_color="#2980b9",
            width=90,
            height=38,
            command=lambda: self._send_tutor_query(self.tutor_input_entry.get()),
        )
        self.tutor_send_btn.pack(side="right")

    def _update_tutor_status_badge(self) -> None:
        """Update the API Key status badge text and color."""
        if self.tutor.is_configured():
            self.api_status_badge.configure(
                text="● Status: API Key Configured",
                text_color="#2ecc71",
            )
        else:
            self.api_status_badge.configure(
                text="● Status: Key Missing (Get free key at aistudio.google.com)",
                text_color="#f39c12",
            )

    def _on_save_api_key(self) -> None:
        """Save entered API key to tutor config and update status badge."""
        key = self.api_key_entry.get().strip()
        self.tutor.set_api_key(key)
        self._update_tutor_status_badge()
        timestamp = time.strftime("%H:%M:%S")
        if key:
            self.tutor_chat_box.insert(
                "end",
                f"[{timestamp}] [System]: Gemini API Key saved and verified.\n\n",
                "tutor_welcome",
            )
        else:
            self.tutor_chat_box.insert(
                "end",
                f"[{timestamp}] [System]: API Key cleared.\n\n",
                "tutor_welcome",
            )
        self.tutor_chat_box.see("end")

    def _send_tutor_query(self, user_question: str) -> None:
        """Send a question to the AI Security Tutor asynchronously."""
        question = user_question.strip()
        if not question:
            return

        # Disable send button, show loading
        self.tutor_send_btn.configure(state="disabled", text="Typing...")
        self.tutor_input_entry.delete(0, "end")

        timestamp = time.strftime("%H:%M:%S")
        self.tutor_chat_box.insert("end", f"[{timestamp}] [Student]:\n{question}\n\n", "user_msg")
        self.tutor_chat_box.see("end")

        def _on_response(response_text: str, is_success: bool) -> None:
            self.after(0, lambda: self._handle_tutor_response(response_text, is_success))

        self.tutor.ask_async(
            prompt=question,
            context=self.latest_threat_context,
            callback=_on_response,
        )

    def _handle_tutor_response(self, response_text: str, is_success: bool) -> None:
        """Render tutor response safely on the main GUI thread."""
        timestamp = time.strftime("%H:%M:%S")
        tag = "tutor_success" if is_success else "tutor_error"
        self.tutor_chat_box.insert("end", f"[{timestamp}] [Glass-Box Tutor]:\n{response_text}\n\n", tag)
        self.tutor_chat_box.see("end")
        self.tutor_send_btn.configure(state="normal", text="➤ Send")

    def _on_ask_tutor_about_alert(self) -> None:
        """Escalate the current alert context directly into the AI Security Tutor."""
        ctx = self.latest_threat_context or {
            "attack_type": "TCP SYN Flood",
            "attacker_ip": "192.168.1.100",
            "port": "80",
        }
        attack_type = ctx.get("attack_type", "Detected Anomaly")
        attacker_ip = ctx.get("attacker_ip", "attacker host")
        port = ctx.get("port", "N/A")

        inquiry = (
            f"Can you break down the recent {attack_type} detected from {attacker_ip} "
            f"on port {port} and suggest how to remediate it?"
        )
        self._show_view("tutor")
        self._send_tutor_query(inquiry)

    def _setup_text_tags(self) -> None:
        """Configure color syntax highlighting tags on underlying text widgets."""
        try:
            # Live traffic box tags
            self.traffic_box._textbox.tag_config("safe", foreground="#2ecc71")
            self.traffic_box._textbox.tag_config(
                "alert", foreground="#ff4d4d", font=("Consolas", 10, "bold")
            )
            self.traffic_box._textbox.tag_config("system", foreground="#3498db")

            # Suppressed noise box tags
            self.suppressed_box._textbox.tag_config("suppressed", foreground="#f39c12")
            self.suppressed_box._textbox.tag_config("system", foreground="#3498db")

            # AI Tutor chat box tags
            self.tutor_chat_box._textbox.tag_config(
                "user_msg", foreground="#3498db", font=("Consolas", 10, "bold")
            )
            self.tutor_chat_box._textbox.tag_config(
                "tutor_success", foreground="#ecf0f1", font=("Consolas", 10)
            )
            self.tutor_chat_box._textbox.tag_config(
                "tutor_error", foreground="#e74c3c", font=("Consolas", 10)
            )
            self.tutor_chat_box._textbox.tag_config(
                "tutor_welcome", foreground="#95a5a6", font=("Consolas", 10)
            )
        except Exception:
            self.traffic_box.tag_config("safe", foreground="#2ecc71")
            self.traffic_box.tag_config("alert", foreground="#ff4d4d")
            self.suppressed_box.tag_config("suppressed", foreground="#f39c12")
            self.tutor_chat_box.tag_config("user_msg", foreground="#3498db")
            self.tutor_chat_box.tag_config("tutor_success", foreground="#ecf0f1")
            self.tutor_chat_box.tag_config("tutor_error", foreground="#e74c3c")

    def _show_view(self, view_name: str) -> None:
        """Switch between Live Monitor, Noise & Exclusions, Rule Tuning, and AI Tutor views."""
        self._current_view = view_name

        # Detach all views
        self.view_live.grid_forget()
        self.view_noise.grid_forget()
        self.view_tuning.grid_forget()
        self.view_tutor.grid_forget()

        # Reset button styles to transparent
        self.nav_live_btn.configure(fg_color="transparent")
        self.nav_noise_btn.configure(fg_color="transparent")
        self.nav_tuning_btn.configure(fg_color="transparent")
        self.nav_tutor_btn.configure(fg_color="transparent")

        active_btn_color = ["#3a7ebf", "#1f538d"]
        if view_name == "live":
            self.view_live.grid(row=0, column=0, sticky="nsew")
            self.nav_live_btn.configure(fg_color=active_btn_color)
        elif view_name == "noise":
            self.view_noise.grid(row=0, column=0, sticky="nsew")
            self.nav_noise_btn.configure(fg_color=active_btn_color)
        elif view_name == "tuning":
            self.view_tuning.grid(row=0, column=0, sticky="nsew")
            self.nav_tuning_btn.configure(fg_color=active_btn_color)
        elif view_name == "tutor":
            self.view_tutor.grid(row=0, column=0, sticky="nsew")
            self.nav_tutor_btn.configure(fg_color=active_btn_color)

    def _clear_traffic_feed(self) -> None:
        """Clear all text entries inside the live network traffic feed."""
        self.traffic_box.delete("1.0", "end")

    def _clear_inspector(self) -> None:
        """Clear all text entries inside the educational threat inspector."""
        self.inspector_box.delete("1.0", "end")

    def _clear_noise_feed(self) -> None:
        """Clear all text entries inside the enterprise noise feed."""
        self.noise_box.delete("1.0", "end")

    def _on_syn_slider_change(self, value: float) -> None:
        """Handle TCP SYN threshold slider adjustment."""
        int_val = int(round(value))
        self.detector.tcp_syn_threshold = int_val
        self.syn_slider_label.configure(
            text=f"TCP SYN Flood / Scan Threshold: {int_val} packets"
        )

    def _on_icmp_slider_change(self, value: float) -> None:
        """Handle ICMP threshold slider adjustment."""
        int_val = int(round(value))
        self.detector.icmp_threshold = int_val
        self.icmp_slider_label.configure(
            text=f"ICMP Echo Request Ping Flood Threshold: {int_val} packets"
        )

    def _on_udp_slider_change(self, value: float) -> None:
        """Handle UDP threshold slider adjustment."""
        int_val = int(round(value))
        self.detector.udp_threshold = int_val
        self.udp_slider_label.configure(
            text=f"UDP Sweep / Flood Threshold: {int_val} datagrams"
        )

    def _on_window_slider_change(self, value: float) -> None:
        """Handle sliding frequency window slider adjustment."""
        float_val = round(float(value), 1)
        self.detector.window_duration = float_val
        self.window_slider_label.configure(
            text=f"Sliding Frequency Window Duration: {float_val:.1f} seconds"
        )

    def _on_multicast_toggle(self) -> None:
        """Handle multicast filter toggle."""
        self.detector.filter_multicast = bool(self.switch_multicast.get())

    def _on_broadcast_toggle(self) -> None:
        """Handle broadcast filter toggle."""
        self.detector.filter_broadcast = bool(self.switch_broadcast.get())

    def _on_add_whitelist(self) -> None:
        """Add an IP address to the detector's whitelist after validation."""
        raw_ip = self.ip_entry.get().strip()
        if not raw_ip:
            return

        try:
            ipaddress.IPv4Address(raw_ip)
            self.detector.add_to_whitelist(raw_ip)
            self.ip_entry.delete(0, "end")
            self._update_whitelist_display()
        except ipaddress.AddressValueError:
            self.active_whitelist_label.configure(
                text=f"Error: '{raw_ip}' is not a valid IPv4 address."
            )

    def _on_clear_whitelist(self) -> None:
        """Clear all whitelisted IP addresses from the detector."""
        self.detector.clear_whitelist()
        self._update_whitelist_display()

    def _update_whitelist_display(self) -> None:
        """Refresh the active whitelist label display."""
        whitelist = sorted(list(self.detector.get_whitelist()))
        if whitelist:
            formatted_list = ", ".join(whitelist)
            self.active_whitelist_label.configure(text=f"Active Whitelist: {formatted_list}")
        else:
            self.active_whitelist_label.configure(text="Active Whitelist: (None)")

    def _start_monitoring(self) -> None:
        """Handle Start Monitoring button action."""
        if not self.sniffer.is_running:
            self.sniffer.start()
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.status_badge.configure(text="● Status: MONITORING", text_color="#2ecc71")
            timestamp = time.strftime("%H:%M:%S")
            self.traffic_box.insert("end", f"[{timestamp}] [SYSTEM] Packet capture started...\n", "system")
            self.traffic_box.see("end")

    def _stop_monitoring(self) -> None:
        """Handle Stop Monitoring button action."""
        if self.sniffer.is_running:
            self.sniffer.stop()
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.status_badge.configure(text="● Status: STOPPED", text_color="#e74c3c")
            timestamp = time.strftime("%H:%M:%S")
            self.traffic_box.insert("end", f"[{timestamp}] [SYSTEM] Packet capture stopped.\n", "system")
            self.traffic_box.see("end")

    def _poll_queue(self) -> None:
        """
        Poll incoming packets from the thread-safe queue.
        Processes up to 50 packets per 50ms tick to maintain high GUI responsiveness.
        Routes NORMAL/ALERT to Live Monitor and SUPPRESSED to Noise View.
        Extracts threat metadata for the AI Security Tutor.
        """
        if not self._is_open:
            return

        packets_processed = 0
        while packets_processed < 50:
            try:
                item = self.packet_queue.get_nowait()
            except queue.Empty:
                break

            status, log_str, explanation = item
            self.total_packets += 1
            self.total_packets_label.configure(text=f"Total Packets: {self.total_packets}")

            timestamp = time.strftime("%H:%M:%S")
            formatted_log = f"[{timestamp}] {log_str}"

            if status == "ALERT":
                self.total_alerts += 1
                self.total_alerts_label.configure(text=f"Alerts: {self.total_alerts}")
                self.traffic_box.insert("end", formatted_log + "\n", "alert")

                # Extract threat telemetry for AI Security Tutor
                attack_type = "Network Attack"
                if "SYN Flood" in log_str:
                    attack_type = "TCP SYN Flood / Port Scan"
                elif "ICMP Ping Flood" in log_str:
                    attack_type = "ICMP Echo Request Ping Flood"
                elif "UDP Sweep" in log_str:
                    attack_type = "UDP Sweep / Flood"

                attacker_ip = "Unknown"
                port = "N/A"
                count = "N/A"
                try:
                    if "detected from " in log_str:
                        parts = log_str.split("detected from ")[1].split(" -> ")
                        attacker_ip = parts[0].strip()
                        target_part = parts[1].split(" ")[0].strip()
                        if ":" in target_part:
                            port = target_part.split(":")[1]
                    if "(" in log_str and " within " in log_str:
                        count = log_str.split("(")[1].split(" within ")[0].strip()
                except Exception:
                    pass

                self.latest_threat_context = {
                    "attack_type": attack_type,
                    "attacker_ip": attacker_ip,
                    "port": port,
                    "packet_count": count,
                    "log": log_str,
                    "explanation": explanation,
                }

                separator = "=" * 70
                threat_entry = (
                    f"\n{separator}\n"
                    f"[{timestamp}] SECURITY THREAT DETECTED\n"
                    f"{separator}\n"
                    f"{explanation}\n"
                )
                self.inspector_box.insert("end", threat_entry)
                self.inspector_box.see("end")

            elif status == "SUPPRESSED":
                self.total_suppressed += 1
                self.total_suppressed_label.configure(text=f"Suppressed: {self.total_suppressed}")
                suppressed_line = f"{formatted_log} (Reason: {explanation})\n"
                self.suppressed_box.insert("end", suppressed_line, "suppressed")
                self.suppressed_box.see("end")

            else:  # status == "NORMAL"
                self.traffic_box.insert("end", formatted_log + "\n", "safe")

            self.traffic_box.see("end")
            packets_processed += 1

        # Memory buffer pruning (keep last ~2500 lines)
        try:
            line_count = int(self.traffic_box._textbox.index("end-1c").split(".")[0])
            if line_count > 2500:
                self.traffic_box._textbox.delete("1.0", "500.0")

            noise_line_count = int(self.suppressed_box._textbox.index("end-1c").split(".")[0])
            if noise_line_count > 2500:
                self.suppressed_box._textbox.delete("1.0", "500.0")

            tutor_line_count = int(self.tutor_chat_box._textbox.index("end-1c").split(".")[0])
            if tutor_line_count > 2500:
                self.tutor_chat_box._textbox.delete("1.0", "500.0")
        except Exception:
            pass

        # Schedule next queue poll in 50 milliseconds
        if self._is_open:
            self._poll_after_id = self.after(50, self._poll_queue)

    def _on_closing(self) -> None:
        """Gracefully terminate sniffer and cancel pending timers before closing window."""
        self._is_open = False
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except Exception:
                pass

        if self.sniffer and self.sniffer.is_running:
            self.sniffer.stop(timeout=1.5)

        self.destroy()
