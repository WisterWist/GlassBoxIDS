"""
detector.py - Threat Detection Engine for Glass-Box IDS.

Inspects incoming Scapy packets for network anomalies, tracks frequency
across rolling time windows using collections.Counter, suppresses enterprise
noise (multicast/mDNS, broadcast/SSDP, whitelists), enforces alert cooldowns,
and produces explainable educational security alerts.
"""

from collections import Counter
import threading
import time
from typing import Dict, Optional, Set, Tuple

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet


class ThreatDetector:
    """
    Threat detection engine for inspecting network packets and identifying
    anomalous traffic patterns like TCP SYN floods, ICMP ping floods, and UDP sweeps.
    Supports dynamic threshold tuning, enterprise noise filtering, and alert cooldowns.
    """

    def __init__(
        self,
        window_duration: float = 5.0,
        tcp_syn_threshold: int = 5,
        icmp_threshold: int = 10,
        udp_threshold: int = 15,
        filter_multicast: bool = True,
        filter_broadcast: bool = True,
        whitelist_ips: Optional[Set[str]] = None,
        cooldown_duration: float = 3.0,
    ) -> None:
        """
        Initialize the ThreatDetector with specified thresholds and filtering policies.

        :param window_duration: Duration of the rolling window in seconds (default: 5.0s).
        :param tcp_syn_threshold: SYN packet count threshold within window (default: 5).
        :param icmp_threshold: ICMP Echo Request threshold within window (default: 10).
        :param udp_threshold: UDP datagram threshold within window (default: 15).
        :param filter_multicast: Filter out multicast / mDNS traffic (default: True).
        :param filter_broadcast: Filter out broadcast / SSDP traffic (default: True).
        :param whitelist_ips: Initial set of IP addresses excluded from threat inspection.
        :param cooldown_duration: Seconds of alert suppression per IP following an alert (default: 3.0s).
        """
        self.window_duration: float = window_duration
        self.tcp_syn_threshold: int = tcp_syn_threshold
        self.icmp_threshold: int = icmp_threshold
        self.udp_threshold: int = udp_threshold

        # Enterprise noise filtering toggles
        self.filter_multicast: bool = filter_multicast
        self.filter_broadcast: bool = filter_broadcast
        self.whitelist_ips: Set[str] = set(whitelist_ips) if whitelist_ips else set()

        # Cooldown management (IP -> timestamp of last triggered alert)
        self.cooldown_duration: float = cooldown_duration
        self.alert_cooldowns: Dict[str, float] = {}

        # Frequency trackers keyed by source IP address
        self.tcp_syn_counts: Counter[str] = Counter()
        self.icmp_counts: Counter[str] = Counter()
        self.udp_counts: Counter[str] = Counter()

        self.window_start: float = time.monotonic()
        self._lock: threading.Lock = threading.Lock()

    def add_to_whitelist(self, ip_address: str) -> bool:
        """Add an IP address to the active exclusion whitelist."""
        clean_ip = ip_address.strip()
        if not clean_ip:
            return False
        with self._lock:
            self.whitelist_ips.add(clean_ip)
        return True

    def remove_from_whitelist(self, ip_address: str) -> bool:
        """Remove an IP address from the active exclusion whitelist."""
        clean_ip = ip_address.strip()
        with self._lock:
            if clean_ip in self.whitelist_ips:
                self.whitelist_ips.remove(clean_ip)
                return True
        return False

    def clear_whitelist(self) -> None:
        """Clear all whitelisted IP addresses."""
        with self._lock:
            self.whitelist_ips.clear()

    def get_whitelist(self) -> Set[str]:
        """Return a copy of the currently whitelisted IP addresses."""
        with self._lock:
            return set(self.whitelist_ips)

    def _is_multicast(self, dst_ip: str, sport: Optional[int], dport: Optional[int]) -> bool:
        """Check if traffic is multicast (224.0.0.0/4, 239.0.0.0/8) or mDNS (port 5353)."""
        if sport == 5353 or dport == 5353 or sport == 5355 or dport == 5355:
            return True
        try:
            first_octet = int(dst_ip.split(".")[0])
            if 224 <= first_octet <= 239:
                return True
        except (ValueError, IndexError):
            pass
        return False

    def _is_broadcast(self, dst_ip: str, sport: Optional[int], dport: Optional[int]) -> bool:
        """Check if traffic is broadcast (255.255.255.255, subnet broadcast) or SSDP (port 1900)."""
        if sport == 1900 or dport == 1900:
            return True
        if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
            return True
        return False

    def _check_and_reset_window(self, current_time: float) -> None:
        """Reset frequency trackers if the current rolling window has expired."""
        if current_time - self.window_start >= self.window_duration:
            self.tcp_syn_counts.clear()
            self.icmp_counts.clear()
            self.udp_counts.clear()
            self.window_start = current_time

    def reset_trackers(self) -> None:
        """Manually clear frequency counters, alert cooldowns, and restart window."""
        with self._lock:
            self.tcp_syn_counts.clear()
            self.icmp_counts.clear()
            self.udp_counts.clear()
            self.alert_cooldowns.clear()
            self.window_start = time.monotonic()

    def process_packet(self, packet: Packet) -> Tuple[str, str, Optional[str]]:
        """
        Evaluate an incoming Scapy packet against threat rules, filtering policies,
        and alert cooldowns.

        :param packet: Scapy Packet instance to inspect.
        :return: A 3-element tuple: (status, log_message, explanation_or_reason)
                 - status: "ALERT", "NORMAL", or "SUPPRESSED"
        """
        # Non-IP packet handling (e.g. ARP or raw Layer 2 frames)
        if not packet.haslayer(IP):
            summary = packet.summary() if hasattr(packet, "summary") else "Unknown Frame"
            return "SUPPRESSED", f"[SUPPRESSED] Non-IPv4 Packet: {summary}", "Non-IPv4 Frame"

        ip_layer = packet[IP]
        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst
        now: float = time.monotonic()

        # Extract transport ports if present
        sport: Optional[int] = None
        dport: Optional[int] = None
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        with self._lock:
            # 1. Whitelist Exclusion Filter
            if src_ip in self.whitelist_ips or dst_ip in self.whitelist_ips:
                matched_ip = src_ip if src_ip in self.whitelist_ips else dst_ip
                log_msg = f"[SUPPRESSED] Whitelisted Traffic: {src_ip} -> {dst_ip}"
                reason = f"IP address {matched_ip} is in active exclusion whitelist"
                return "SUPPRESSED", log_msg, reason

            # 2. Multicast / mDNS Enterprise Filter
            if self.filter_multicast and self._is_multicast(dst_ip, sport, dport):
                log_msg = f"[SUPPRESSED] Multicast/mDNS: {src_ip} -> {dst_ip}"
                if dport:
                    log_msg += f":{dport}"
                reason = "Multicast / mDNS Discovery Noise (224.0.0.0/4 or UDP 5353)"
                return "SUPPRESSED", log_msg, reason

            # 3. Broadcast / SSDP UPnP Enterprise Filter
            if self.filter_broadcast and self._is_broadcast(dst_ip, sport, dport):
                log_msg = f"[SUPPRESSED] Broadcast/SSDP: {src_ip} -> {dst_ip}"
                if dport:
                    log_msg += f":{dport}"
                reason = "Broadcast / SSDP UPnP Noise (255.255.255.255 or UDP 1900)"
                return "SUPPRESSED", log_msg, reason

            # Window rollover check
            self._check_and_reset_window(now)

            # 4. Rule 1: TCP SYN Flood / Scan Check
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                flags_str: str = str(tcp_layer.flags)

                if "S" in flags_str:
                    self.tcp_syn_counts[src_ip] += 1
                    count = self.tcp_syn_counts[src_ip]

                    if count > self.tcp_syn_threshold:
                        last_alert = self.alert_cooldowns.get(src_ip, 0.0)
                        if now - last_alert < self.cooldown_duration:
                            # Cooldown active: suppress alert storming
                            remaining = self.cooldown_duration - (now - last_alert)
                            log_msg = (
                                f"[NORMAL] (Alert Cooldown: {remaining:.1f}s) TCP SYN from "
                                f"{src_ip}:{sport} -> {dst_ip}:{dport} ({count} in window)"
                            )
                            return "NORMAL", log_msg, None

                        # Cooldown expired: trigger alert and record timestamp
                        self.alert_cooldowns[src_ip] = now
                        alert_log = (
                            f"[ALERT] TCP SYN Flood / Scan detected from {src_ip} -> "
                            f"{dst_ip}:{dport} ({count} SYN packets within {self.window_duration:.1f}s window)"
                        )
                        explanation = (
                            f"[Glass-Box Explanation - TCP SYN Flood / Scan]\n"
                            f"Source IP {src_ip} transmitted {count} TCP packets with the SYN ('S') flag set "
                            f"within {self.window_duration:.1f} seconds, exceeding the safety threshold of {self.tcp_syn_threshold}.\n"
                            f"Mechanics: Standard TCP connections establish state via a 3-way handshake (SYN -> SYN-ACK -> ACK). "
                            f"In a SYN Flood (Denial of Service) or Half-Open SYN Scan, the client emits rapid SYN requests "
                            f"without completing the handshake. This consumes server backlog queue resources or probes listening "
                            f"ports while attempting to evade full TCP session logging."
                        )
                        return "ALERT", alert_log, explanation

                    normal_log = (
                        f"[NORMAL] TCP SYN from {src_ip}:{sport} -> {dst_ip}:{dport} "
                        f"(SYN Count: {count}/{self.tcp_syn_threshold})"
                    )
                    return "NORMAL", normal_log, None

                # Normal TCP packet without SYN flag (e.g., ACK, FIN, PSH)
                normal_log = f"[NORMAL] TCP from {src_ip}:{sport} -> {dst_ip}:{dport} [Flags: {flags_str}]"
                return "NORMAL", normal_log, None

            # 5. Rule 2: ICMP Ping Flood Check
            if packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                icmp_type: int = icmp_layer.type
                icmp_code: int = icmp_layer.code

                if icmp_type == 8:  # Echo Request
                    self.icmp_counts[src_ip] += 1
                    count = self.icmp_counts[src_ip]

                    if count > self.icmp_threshold:
                        last_alert = self.alert_cooldowns.get(src_ip, 0.0)
                        if now - last_alert < self.cooldown_duration:
                            remaining = self.cooldown_duration - (now - last_alert)
                            log_msg = (
                                f"[NORMAL] (Alert Cooldown: {remaining:.1f}s) ICMP Echo Request from "
                                f"{src_ip} -> {dst_ip} ({count} in window)"
                            )
                            return "NORMAL", log_msg, None

                        self.alert_cooldowns[src_ip] = now
                        alert_log = (
                            f"[ALERT] ICMP Ping Flood detected from {src_ip} -> {dst_ip} "
                            f"({count} Echo Requests within {self.window_duration:.1f}s window)"
                        )
                        explanation = (
                            f"[Glass-Box Explanation - ICMP Ping Flood]\n"
                            f"Source IP {src_ip} transmitted {count} ICMP Echo Request (Type 8) packets "
                            f"within {self.window_duration:.1f} seconds, exceeding the safety threshold of {self.icmp_threshold}.\n"
                            f"Mechanics: ICMP Echo Requests test reachability. Flooding a target with Echo Requests "
                            f"forces the operating system to process each packet and reply with Echo Replies (Type 0). "
                            f"This storm exhausts incoming bandwidth, taxes kernel network stacks, and degrades host performance."
                        )
                        return "ALERT", alert_log, explanation

                    normal_log = (
                        f"[NORMAL] ICMP Echo Request from {src_ip} -> {dst_ip} "
                        f"(Echo Count: {count}/{self.icmp_threshold})"
                    )
                    return "NORMAL", normal_log, None

                # Other ICMP types (e.g. Type 0 Echo Reply)
                normal_log = f"[NORMAL] ICMP (Type {icmp_type}, Code {icmp_code}) from {src_ip} -> {dst_ip}"
                return "NORMAL", normal_log, None

            # 6. Rule 3: UDP Sweep / Flood Check
            if packet.haslayer(UDP):
                self.udp_counts[src_ip] += 1
                count = self.udp_counts[src_ip]

                if count > self.udp_threshold:
                    last_alert = self.alert_cooldowns.get(src_ip, 0.0)
                    if now - last_alert < self.cooldown_duration:
                        remaining = self.cooldown_duration - (now - last_alert)
                        log_msg = (
                            f"[NORMAL] (Alert Cooldown: {remaining:.1f}s) UDP from "
                            f"{src_ip}:{sport} -> {dst_ip}:{dport} ({count} in window)"
                        )
                        return "NORMAL", log_msg, None

                    self.alert_cooldowns[src_ip] = now
                    alert_log = (
                        f"[ALERT] UDP Sweep / Flood detected from {src_ip} -> {dst_ip}:{dport} "
                        f"({count} datagrams within {self.window_duration:.1f}s window)"
                    )
                    explanation = (
                        f"[Glass-Box Explanation - UDP Sweep / Flood]\n"
                        f"Source IP {src_ip} transmitted {count} UDP datagrams within {self.window_duration:.1f} seconds, "
                        f"exceeding the safety threshold of {self.udp_threshold}.\n"
                        f"Mechanics: UDP is connectionless without handshake verification or flow control. "
                        f"High volumes of UDP datagrams sent across arbitrary ports force the destination host "
                        f"to scan listening sockets and dispatch ICMP Port Unreachable packets, consuming CPU and bandwidth."
                    )
                    return "ALERT", alert_log, explanation

                normal_log = (
                    f"[NORMAL] UDP from {src_ip}:{sport} -> {dst_ip}:{dport} "
                    f"(UDP Count: {count}/{self.udp_threshold})"
                )
                return "NORMAL", normal_log, None

            # 7. Other IP Protocols (IGMP, GRE, ESP, etc.)
            proto: int = ip_layer.proto
            normal_log = f"[NORMAL] IPv4 Protocol {proto} packet from {src_ip} -> {dst_ip}"
            return "NORMAL", normal_log, None
