"""
sniffer.py - Threaded Network Packet Sniffer for Glass-Box IDS.

Captures live network packets using Scapy, processes them with ThreatDetector,
and pushes detection logs and explainable alerts into a thread-safe queue.
Runs asynchronously inside a daemon background thread.
"""

import logging
import queue
import threading
from typing import Optional, Tuple

from scapy.all import sniff
from scapy.packet import Packet

from detector import ThreatDetector

# Setup module-level logger
logger = logging.getLogger(__name__)


class NetworkSniffer:
    """
    Asynchronous network packet sniffer that captures packets on a background daemon
    thread, evaluates them using a ThreatDetector instance, and delivers detection
    results into a thread-safe queue.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        detector: ThreatDetector,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ) -> None:
        """
        Initialize the NetworkSniffer.

        :param packet_queue: Thread-safe queue instance to receive (status, log, explanation) tuples.
        :param detector: Instance of ThreatDetector to inspect packets.
        :param interface: Optional network interface name or IP to bind sniffing.
        :param bpf_filter: Optional Berkeley Packet Filter (BPF) string (e.g., 'ip').
        """
        self.packet_queue: queue.Queue = packet_queue
        self.detector: ThreatDetector = detector
        self.interface: Optional[str] = interface
        self.bpf_filter: Optional[str] = bpf_filter

        self._is_running: bool = False
        self._thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        """Return True if the sniffer is actively capturing packets."""
        return self._is_running

    def _packet_callback(self, packet: Packet) -> None:
        """
        Callback invoked by Scapy for each captured packet.
        Evaluates the frame with ThreatDetector and places the output into the queue.
        Exceptions are caught gracefully so malformed frames do not disrupt capture.
        """
        try:
            result: Tuple[str, str, Optional[str]] = self.detector.process_packet(packet)
            self.packet_queue.put(result)
        except Exception as exc:
            error_log = f"[ERROR] Malformed or unprocessable packet frame: {exc}"
            logger.error(error_log, exc_info=False)
            self.packet_queue.put(("SUPPRESSED", error_log, "Malformed Frame Exception"))

    def _sniff_worker(self) -> None:
        """
        Worker routine running inside the background daemon thread.
        Uses short timeouts and a stop filter to ensure prompt, clean shutdowns.
        """
        logger.info("NetworkSniffer daemon thread started.")
        while self._is_running:
            try:
                sniff(
                    prn=self._packet_callback,
                    stop_filter=lambda _pkt: not self._is_running,
                    store=False,  # Prevent memory exhaustion by not storing packets
                    timeout=1.0,  # Periodic unblocking to check self._is_running flag
                    iface=self.interface,
                    filter=self.bpf_filter,
                )
            except Exception as exc:
                if not self._is_running:
                    break
                logger.error("Exception in packet capture loop: %s", exc)

        logger.info("NetworkSniffer daemon thread stopped.")

    def start(self) -> None:
        """
        Start the background packet sniffing loop inside a daemon thread.
        Does not block execution.
        """
        if self._is_running:
            logger.warning("NetworkSniffer is already running.")
            return

        self._is_running = True
        self._thread = threading.Thread(
            target=self._sniff_worker,
            name="GlassBox-SnifferThread",
            daemon=True,
        )
        self._thread.start()
        logger.info("NetworkSniffer started in daemon thread.")

    def stop(self, timeout: Optional[float] = 2.0) -> None:
        """
        Stop the background packet sniffing loop.

        :param timeout: Maximum seconds to wait for background thread termination.
        """
        if not self._is_running:
            return

        self._is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("NetworkSniffer successfully stopped.")
