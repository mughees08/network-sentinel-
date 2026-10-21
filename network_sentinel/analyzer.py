"""Offline packet-capture analysis and explainable heuristic detections."""
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, TCP, UDP, rdpcap
from scapy.packet import Packet

from .models import Alert


def _safe_name(value: bytes | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".") or None
    return str(value).rstrip(".") or None


def _packet_protocol(packet: Packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        return "Other IP"
    return "Other"


def analyze_packets(
    packets: list[Packet],
    capture_name: str = "in-memory",
    syn_threshold: int = 20,
    dns_threshold: int = 50,
) -> dict[str, Any]:
    """Analyze already-loaded packets and return a JSON-serializable report."""
    protocols: Counter[str] = Counter()
    source_packets: Counter[str] = Counter()
    destination_packets: Counter[str] = Counter()
    source_bytes: Counter[str] = Counter()
    dns_queries: Counter[str] = Counter()
    http_hosts: Counter[str] = Counter()
    syn_destinations: dict[str, set[int]] = defaultdict(set)
    syn_counts: Counter[str] = Counter()
    total_bytes = 0
    first_ts: float | None = None
    last_ts: float | None = None
    cleartext_http_packets = 0

    for packet in packets:
        size = len(packet)
        total_bytes += size
        protocols[_packet_protocol(packet)] += 1
        try:
            ts = float(packet.time)
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        except (AttributeError, TypeError, ValueError):
            pass

        src = dst = None
        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
        elif packet.haslayer(IPv6):
            src, dst = packet[IPv6].src, packet[IPv6].dst

        if src:
            source_packets[src] += 1
            source_bytes[src] += size
        if dst:
            destination_packets[dst] += 1

        if packet.haslayer(DNS) and packet[DNS].qd is not None:
            query = packet[DNS].qd
            if packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                name = _safe_name(query.qname)
                if name:
                    dns_queries[name] += 1

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = int(tcp.flags)
            # SYN set and ACK not set: initial connection attempt.
            if src and dst and (flags & 0x02) and not (flags & 0x10):
                syn_counts[src] += 1
                syn_destinations[src].add(int(tcp.dport))
            if int(tcp.dport) == 80 or int(tcp.sport) == 80:
                cleartext_http_packets += 1
                # HTTP layer may not be dissected if the payload is malformed
                # or a non-HTTP service uses port 80.
                host = None
                if packet.haslayer("HTTP") and getattr(packet["HTTP"], "Host", None):
                    host = _safe_name(packet["HTTP"].Host)
                if host:
                    http_hosts[host] += 1

    alerts: list[Alert] = []
    for src, count in syn_counts.items():
        ports = len(syn_destinations[src])
        if count >= syn_threshold and ports >= 10:
            alerts.append(Alert(
                severity="medium",
                rule_id="NS-101",
                title="Possible SYN scan pattern",
                evidence=f"{src} sent {count} initial SYN packets across {ports} destination ports.",
                recommendation="Validate against expected asset behavior and review destination ports and timestamps.",
            ))

    total_dns = sum(dns_queries.values())
    if total_dns >= dns_threshold:
        alerts.append(Alert(
            severity="low",
            rule_id="NS-201",
            title="High DNS query volume in capture",
            evidence=f"Observed {total_dns} DNS query packets; configured threshold is {dns_threshold}.",
            recommendation="Check whether the capture duration and host activity explain the volume; inspect repeated and unusual names.",
        ))

    if cleartext_http_packets:
        alerts.append(Alert(
            severity="info",
            rule_id="NS-301",
            title="Cleartext HTTP-port traffic observed",
            evidence=f"{cleartext_http_packets} TCP packet(s) used source or destination port 80.",
            recommendation="Confirm whether cleartext HTTP is expected; prefer HTTPS for sensitive traffic. Port 80 alone does not prove HTTP content.",
        ))

    duration = max(0.0, last_ts - first_ts) if first_ts is not None and last_ts is not None else None
    return {
        "tool": "Network Sentinel",
        "schema_version": "1.0",
        "capture": capture_name,
        "summary": {
            "packet_count": len(packets),
            "total_bytes": total_bytes,
            "duration_seconds": round(duration, 3) if duration is not None else None,
            "unique_source_ips": len(source_packets),
            "unique_destination_ips": len(destination_packets),
        },
        "protocols": dict(protocols.most_common()),
        "top_talkers": [
            {"ip": ip, "packets": count, "bytes": source_bytes[ip]}
            for ip, count in source_packets.most_common(10)
        ],
        "top_destinations": [
            {"ip": ip, "packets": count}
            for ip, count in destination_packets.most_common(10)
        ],
        "dns_queries": [
            {"name": name, "count": count}
            for name, count in dns_queries.most_common(100)
        ],
        "http_hosts": [
            {"host": host, "count": count}
            for host, count in http_hosts.most_common(100)
        ],
        "alerts": [alert.to_dict() for alert in alerts],
        "disclaimer": "Heuristic findings are leads for analyst review, not proof of malicious activity.",
    }


def analyze_pcap(
    path: str | Path,
    syn_threshold: int = 20,
    dns_threshold: int = 50,
) -> dict[str, Any]:
    """Read and analyze a PCAP/PCAPNG file from disk."""
    capture_path = Path(path)
    if not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")
    packets = rdpcap(str(capture_path))
    return analyze_packets(
        list(packets),
        capture_name=capture_path.name,
        syn_threshold=syn_threshold,
        dns_threshold=dns_threshold,
    )
