# 🧊 Glass-Box IDS — Explainable Network Intrusion Detection System & AI Security Tutor

![Python](https://img.shields.io/badge/Python-3.14-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet_Engine-2ecc71?style=for-the-badge)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-1f6aa5?style=for-the-badge)
![Gemini API](https://img.shields.io/badge/AI_Tutor-Google_Gemini-8E75B2?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows_11-0078D6?style=for-the-badge&logo=windows&logoColor=white)

**Glass-Box IDS** is a lightweight, host-based Intrusion Detection System (IDS) engineered to replace "black-box" Command Line Interface (CLI) security monitors with real-time visual packet deconstruction and AI-assisted incident response. 

Designed to run natively on Windows 11 without the heavy memory overhead of Linux virtual machines (~76.9 MB RAM under active flood conditions vs. 2,000+ MB for virtualized labs), Glass-Box IDS pairs a deterministic rolling-window heuristic engine with an embedded **AI Security Tutor** that translates live threat telemetry into actionable firewall rules and protocol breakdowns.

> 🔗 **Companion Red-Team Testbench:** Pair this monitor with [**Project S.A.Y. (Safely Attack Yourself)**](https://github.com/WisterWist/SafelyAttackYourself) to inject controlled Layer 2 synthetic attacks (TCP SYN floods, ICMP ping storms, and UDP port sweeps) directly on a single host machine.

---

## 📸 Dashboard Preview

<img width="1036" height="711" alt="image" src="https://github.com/user-attachments/assets/e51b7ae0-6f32-417f-add8-8a768bae45ba" />



---

## 🚀 Key Engineering Features

### 1. Multi-Vector Rolling-Window Heuristic Engine (`detector.py`)
* **Stateless Payload Stripping:** Inspects IPv4 headers and transport control flags (`store=False`) to prevent memory leaks during extended capture sessions.
* **5.0-Second Sliding Window:** Tracks per-source packet velocity and triggers alerts with a 3.0-second alert cooldown debounce:
  * **Rule 1 — TCP SYN Burst / Half-Open Scan:** Flags `> 5` TCP `SYN` packets within `5.0s`.
  * **Rule 2 — ICMP Ping Flood:** Flags `> 10` ICMP Echo Requests (`Type 8`) within `5.0s`.
  * **Rule 3 — UDP Port Sweep:** Flags `> 15` UDP datagrams sweeping across target ports within `5.0s`.
* **Live Rule Tuning:** Interactive dashboard sliders allow real-time threshold adjustments without restarting the packet sniffer.

### 2. Enterprise Broadcast & Multicast Noise Suppression
* Automatically filters ambient enterprise/campus Wi-Fi chatter so real threat signatures remain visible:
  * **mDNS Discovery:** `224.0.0.0/4` and UDP port `5353`.
  * **SSDP / UPnP & Broadcast:** `239.0.0.0/8`, `255.255.255.255`, and UDP port `1900`.
  * **Layer 2 Non-IPv4 / ARP:** Isolates non-IPv4 frames into a dedicated **Filtered Enterprise Noise Feed**.
* **Dynamic IPv4 Whitelisting:** Validated via Python's `ipaddress` library to exclude trusted hosts on the fly.

### 3. Embedded AI Security Tutor (`tutor.py`)
* **One-Click Telemetry Escalation:** Clicking **"✨ Ask AI Tutor About This Alert"** extracts live attack metadata (Attacker IP, Target Port, Protocol, Packet Count) and switches to the AI Security Tutor view.
* **Zero-Dependency REST Architecture:** Uses Python's standard `urllib.request` with exponential backoff retry logic (handling HTTP `503`/`429` spikes) and automatic model fallback (`gemini-3.6-flash`).
* **Actionable Defensive Remediation:** Generates context-aware **Windows Defender Firewall (PowerShell)** commands (`New-NetFirewallRule`), Linux **`iptables`** rate-limiting rules, and **Snort IDS signatures** tailored to the exact attacker IP and port captured on the wire.

### 4. Thread-Safe Asynchronous Architecture (`sniffer.py` & `ui.py`)
* Decouples promiscuous Npcap packet capture and HTTPS AI queries into daemon background threads (`threading.Thread`), communicating with the `CustomTkinter` main loop exclusively via thread-safe `queue.Queue` polling (`after(50, ...)`).

---

## 🗂️ Project Architecture

* `main.py` — Application entry point & controller wiring
* `sniffer.py` — Asynchronous Scapy Npcap promiscuous packet sniffer
* `detector.py` — Rolling-window heuristic engine & enterprise noise filter
* `ui.py` — 4-view CustomTkinter dark-mode desktop interface
* `tutor.py` — Asynchronous Gemini REST client with exponential backoff
* `config.example.json` — Safe configuration template for BYOK Gemini API key
* `logo.webp` — Dashboard visual branding asset

---

## ⚙️ Prerequisites & Installation

* **OS:** Windows 10 / 11
* **Python:** Python 3.10+ (Tested on Python 3.14)
* **Packet Capture Driver:** Install [**Npcap**](https://npcap.com/) *(Check **"Install Npcap in WinPcap API-compatible Mode"** during installation)*.
* **Install Dependencies:** `pip install scapy customtkinter pillow`
* **Launch Dashboard (Run PowerShell as Administrator):** `python main.py`

---

## 📊 Splunk SIEM Ingestion & Triage (`_json` / `SPL`)
Glass-Box IDS outputs structured JSON telemetry ready for direct ingestion into **Splunk Enterprise**. 

### 1. Parsed JSON Telemetry & Field Extraction
<img width="1908" height="909" alt="image" src="https://github.com/user-attachments/assets/e8740a61-61c2-47a6-81a4-80f4beff33e3" />


### 2. Automated SOC Alert Aggregation via SPL
```spl
source="glassbox_alerts.json" | spath | stats count as "Total Alerts", sum(packet_count) as "Total Packets", values(alert_type) as "Detected Signatures", values(severity) as "Severity" by src_ip, dst_ip
```
<img width="1919" height="475" alt="image" src="https://github.com/user-attachments/assets/7eeb8119-71f9-4dd0-bfdc-784182686f87" />


## 📊 Resource Benchmark (Host vs. Virtualized Lab)

| Environment Configuration | Operational State | Host RAM Consumed | CPU Utilization |
| :--- | :--- | :--- | :--- |
| **Kali Linux VM (Snort Control Baseline)** | Idle / Active Monitoring | ~2,000+ MB | High |
| **Glass-Box IDS (Native Windows 11)** | Idle | ~70.3 MB | 0.0% |
| **Glass-Box IDS (Native Windows 11)** | Active (Under 500-pkt SYN Flood) | ~76.9 MB | 1.2% |

---

## 👨‍💻 Author

**Muhammad Arif Bin Azman**  
Bachelor of Computer Science (Cyber Security) (Hons.)  
Universiti Tenaga Nasional (UNITEN)
