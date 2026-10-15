"""
main.py - Entry Point for the Glass-Box Intrusion Detection System.

Connects the ThreatDetector analysis engine, Scapy-powered NetworkSniffer,
SecurityTutor AI assistant, thread-safe communication queue, and
CustomTkinter Graphical User Interface.
"""

import queue

from detector import ThreatDetector
from sniffer import NetworkSniffer
from tutor import SecurityTutor
from ui import GlassBoxUI


def main() -> None:
    """Initialize core IDS components and launch the UI event loop."""
    # 1. Initialize threat detection engine with dynamic defaults
    detector = ThreatDetector(
        window_duration=5.0,
        tcp_syn_threshold=5,
        icmp_threshold=10,
        udp_threshold=15,
        filter_multicast=True,
        filter_broadcast=True,
    )

    # 2. Initialize thread-safe communication queue
    packet_queue = queue.Queue()

    # 3. Initialize background network packet sniffer
    sniffer = NetworkSniffer(
        packet_queue=packet_queue,
        detector=detector,
    )

    # 4. Initialize AI Security Tutor engine
    tutor = SecurityTutor()

    # 5. Initialize and launch the CustomTkinter GUI dashboard
    app = GlassBoxUI(
        packet_queue=packet_queue,
        sniffer=sniffer,
        detector=detector,
        tutor=tutor,
    )
    app.mainloop()


if __name__ == "__main__":
    main()
