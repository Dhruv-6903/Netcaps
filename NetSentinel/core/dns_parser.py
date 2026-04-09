"""Parse DNS packets and detect suspicious activity."""
import math
import socket
import struct
from collections import defaultdict
import dpkt


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


SUSPICIOUS_TAGS = {
    "dns_tunneling": "DNS Tunneling (long label)",
    "beaconing": "DNS Beaconing",
    "c2_dga": "NXDOMAIN / C2 DGA",
    "exfiltration": "TXT Query Exfiltration",
    "ddos_amp": "ANY Query (DDoS amplification)",
    "fast_flux": "Fast-Flux DNS (low TTL)",
    "cdn_or_fastflux": "Multiple A records (CDN or fast-flux)",
    "dga": "High-entropy subdomain (DGA)",
}

QTYPE_MAP = {
    dpkt.dns.DNS_A: "A",
    dpkt.dns.DNS_AAAA: "AAAA",
    dpkt.dns.DNS_MX: "MX",
    dpkt.dns.DNS_TXT: "TXT",
    dpkt.dns.DNS_PTR: "PTR",
    dpkt.dns.DNS_CNAME: "CNAME",
    dpkt.dns.DNS_NS: "NS",
    dpkt.dns.DNS_SOA: "SOA",
    dpkt.dns.DNS_SRV: "SRV",
    255: "ANY",
}


class DnsParser:
    """Parse DNS queries and responses, tag suspicious events."""

    def __init__(self):
        self._events = []
        self._query_times = defaultdict(list)   # domain -> [ts, ...]
        self._pending = {}  # txid -> (ts, query)

    def process_packet(self, ts: float, buf: bytes, eth) -> None:
        if eth is None:
            return
        try:
            self._process(ts, buf, eth)
        except Exception:
            pass

    def _process(self, ts: float, buf: bytes, eth) -> None:
        ip_layer = None
        if isinstance(eth.data, dpkt.ip.IP):
            ip_layer = eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip_layer = eth.data
        else:
            return

        if not isinstance(ip_layer.data, dpkt.udp.UDP):
            return

        udp = ip_layer.data
        if udp.dport != 53 and udp.sport != 53:
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

        try:
            dns = dpkt.dns.DNS(bytes(udp.data))
        except Exception:
            return

        qtype_str = "A"
        fqdn = ""
        if dns.qd:
            q = dns.qd[0]
            fqdn = q.name
            qtype_str = QTYPE_MAP.get(q.type, str(q.type))

        is_response = dns.qr == dpkt.dns.DNS_R
        is_nxdomain = is_response and dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN
        answer_count = len(dns.an) if is_response else 0

        response_ips = []
        min_ttl = None
        cnames = []
        if is_response:
            for rr in dns.an:
                try:
                    if rr.type == dpkt.dns.DNS_A:
                        response_ips.append(socket.inet_ntoa(rr.rdata))
                    elif rr.type == dpkt.dns.DNS_AAAA:
                        response_ips.append(socket.inet_ntop(socket.AF_INET6, rr.rdata))
                    elif rr.type == dpkt.dns.DNS_CNAME:
                        cnames.append(rr.rdata if isinstance(rr.rdata, str) else rr.rdata.decode("utf-8", errors="ignore"))
                    if min_ttl is None or rr.ttl < min_ttl:
                        min_ttl = rr.ttl
                except Exception:
                    pass

        # Latency
        latency_ms = 0.0
        txid = dns.id
        if not is_response:
            self._pending[txid] = ts
        else:
            if txid in self._pending:
                latency_ms = (ts - self._pending.pop(txid)) * 1000.0

        # Suspicious tags
        tags = []
        if fqdn:
            labels = fqdn.split(".")
            if labels:
                max_label_len = max(len(l) for l in labels)
                if max_label_len > 50:
                    tags.append("dns_tunneling")
                subdomain = labels[0] if len(labels) > 2 else ""
                if subdomain and _shannon_entropy(subdomain) > 3.5:
                    tags.append("dga")

        if is_nxdomain:
            tags.append("c2_dga")

        if qtype_str == "TXT":
            tags.append("exfiltration")

        if qtype_str == "ANY":
            tags.append("ddos_amp")

        if min_ttl is not None and min_ttl < 60:
            tags.append("fast_flux")

        if answer_count > 4 and len(response_ips) > 4:
            tags.append("cdn_or_fastflux")

        # Beaconing check
        if fqdn and not is_response:
            self._query_times[fqdn].append(ts)
            # keep only last 60s
            cutoff = ts - 60.0
            self._query_times[fqdn] = [t for t in self._query_times[fqdn] if t >= cutoff]
            if len(self._query_times[fqdn]) > 50:
                tags.append("beaconing")

        event = {
            "fqdn": fqdn,
            "query_type": qtype_str,
            "response_ips": response_ips,
            "cnames": cnames,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "timestamp": ts,
            "ttl": min_ttl,
            "answer_count": answer_count,
            "is_nxdomain": is_nxdomain,
            "latency_ms": latency_ms,
            "is_response": is_response,
            "tags": tags,
        }
        self._events.append(event)

    @property
    def events(self):
        return self._events
