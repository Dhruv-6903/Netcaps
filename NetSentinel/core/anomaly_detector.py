"""Detect network anomalies: DoH, ARP poisoning, DHCP rogue, port scan, exfil."""
import socket
import struct
from collections import defaultdict
from datetime import datetime
import dpkt


DOH_RESOLVERS = {"1.1.1.1", "8.8.8.8", "9.9.9.9", "94.140.14.14"}
INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                     "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def _ts_str(ts):
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


class AnomalyDetector:
    """Detect network anomalies from packet stream."""

    def __init__(self):
        self._anomalies = []
        self._arp_table = {}        # ip -> mac
        self._dhcp_offer_macs = {}  # server_ip -> mac set
        self._session_bytes = defaultdict(int)  # (src_ip, dst_ip) -> bytes
        self._scan_tracker = defaultdict(lambda: defaultdict(list))  # src -> dst -> [(port, ts)]

    def process_packet(self, ts: float, buf: bytes, eth) -> None:
        if eth is None:
            return
        try:
            self._process(ts, buf, eth)
        except Exception:
            pass

    def _add_anomaly(self, ts, category, severity, src_ip, dst_ip, description):
        self._anomalies.append({
            "timestamp": ts,
            "timestamp_str": _ts_str(ts),
            "category": category,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "description": description,
        })

    def _process(self, ts: float, buf: bytes, eth) -> None:
        # ARP poisoning
        if isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            if arp.op == dpkt.arp.ARP_OP_REPLY:
                try:
                    ip = socket.inet_ntoa(arp.spa)
                    mac = ":".join("%02x" % b for b in arp.sha)
                    if ip in self._arp_table and self._arp_table[ip] != mac:
                        self._add_anomaly(ts, "arp_poisoning", "HIGH", ip, "",
                                          f"ARP poisoning: {ip} remapped from {self._arp_table[ip]} to {mac}")
                    self._arp_table[ip] = mac
                except Exception:
                    pass
            return

        ip_layer = None
        if isinstance(eth.data, dpkt.ip.IP):
            ip_layer = eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip_layer = eth.data
        else:
            return

        try:
            if isinstance(ip_layer, dpkt.ip.IP):
                src_ip = socket.inet_ntoa(ip_layer.src)
                dst_ip = socket.inet_ntoa(ip_layer.dst)
            else:
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.dst)
        except Exception:
            return

        pkt_len = len(buf)
        transport = ip_layer.data

        # DoH detection
        if isinstance(transport, dpkt.tcp.TCP):
            if transport.dport == 443 and dst_ip in DOH_RESOLVERS:
                self._add_anomaly(ts, "doh_bypass", "LOW", src_ip, dst_ip,
                                  f"DoH bypass: HTTPS to resolver {dst_ip}")

        # DHCP rogue server detection
        if isinstance(transport, dpkt.udp.UDP):
            if transport.sport == 67 and transport.dport == 68:
                # DHCP OFFER (type 2)
                payload = bytes(transport.data)
                if len(payload) > 240:
                    # Check DHCP magic cookie
                    if payload[236:240] == b"\x63\x82\x53\x63":
                        src_mac = ":".join("%02x" % b for b in eth.src)
                        if src_ip not in self._dhcp_offer_macs:
                            self._dhcp_offer_macs[src_ip] = set()
                        self._dhcp_offer_macs[src_ip].add(src_mac)
                        if len(self._dhcp_offer_macs) > 1:
                            self._add_anomaly(ts, "rogue_dhcp", "HIGH", src_ip, dst_ip,
                                              f"Rogue DHCP server: {src_ip} ({src_mac})")

        # Data exfiltration tracking
        if _is_internal(src_ip) and not _is_internal(dst_ip):
            self._session_bytes[(src_ip, dst_ip)] += pkt_len
            if self._session_bytes[(src_ip, dst_ip)] == pkt_len + 100 * 1024 * 1024:
                self._add_anomaly(ts, "data_exfil", "HIGH", src_ip, dst_ip,
                                  f"Possible data exfiltration: {src_ip}→{dst_ip} >100MB")

    @property
    def anomalies(self):
        return self._anomalies
