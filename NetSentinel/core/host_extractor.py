"""Extract host information from network packets."""
import math
import socket
import struct
from collections import defaultdict
import dpkt


def _ttl_window_os(ttl: int, window: int) -> str:
    if ttl <= 64:
        if window == 5840:
            return "Linux 2.4-2.6"
        if window == 65535:
            return "macOS/iOS"
        return "Linux/Unix"
    if ttl <= 128:
        if window == 8192:
            return "Windows Vista+"
        if window == 65535:
            return "Windows XP"
        return "Windows"
    if ttl <= 255:
        if window == 4128:
            return "Cisco IOS"
        if window == 8760:
            return "Solaris"
        return "Network Device"
    return "Unknown"


def _parse_tls_sni(payload: bytes) -> str:
    """Extract SNI from TLS ClientHello payload."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return ""
        # Record layer: type(1) + version(2) + length(2) + handshake
        rec_len = struct.unpack("!H", payload[3:5])[0]
        if len(payload) < 5 + rec_len:
            return ""
        hs = payload[5:]
        if hs[0] != 0x01:  # ClientHello
            return ""
        # Handshake: type(1) + length(3) + version(2) + random(32) + ...
        offset = 4 + 2 + 32
        if len(hs) < offset + 1:
            return ""
        sess_len = hs[offset]
        offset += 1 + sess_len
        if len(hs) < offset + 2:
            return ""
        cipher_len = struct.unpack("!H", hs[offset:offset+2])[0]
        offset += 2 + cipher_len
        if len(hs) < offset + 1:
            return ""
        comp_len = hs[offset]
        offset += 1 + comp_len
        if len(hs) < offset + 2:
            return ""
        ext_total = struct.unpack("!H", hs[offset:offset+2])[0]
        offset += 2
        end = offset + ext_total
        while offset + 4 <= end and offset + 4 <= len(hs):
            ext_type = struct.unpack("!H", hs[offset:offset+2])[0]
            ext_len = struct.unpack("!H", hs[offset+2:offset+4])[0]
            offset += 4
            if ext_type == 0x0000:  # SNI
                if offset + 2 <= len(hs):
                    sni_list_len = struct.unpack("!H", hs[offset:offset+2])[0]
                    p = offset + 2
                    while p < offset + 2 + sni_list_len and p + 3 <= len(hs):
                        name_type = hs[p]
                        name_len = struct.unpack("!H", hs[p+1:p+3])[0]
                        p += 3
                        if name_type == 0 and p + name_len <= len(hs):
                            return hs[p:p+name_len].decode("utf-8", errors="ignore")
                        p += name_len
            offset += ext_len
    except Exception:
        pass
    return ""


class HostExtractor:
    """Extract and track host information from packets."""

    def __init__(self):
        self._hosts = {}  # ip -> host dict
        self._arp_table = {}  # ip -> mac

    def _get_or_create(self, ip: str) -> dict:
        if ip not in self._hosts:
            self._hosts[ip] = {
                "ip": ip,
                "mac": "",
                "hostnames": set(),
                "os_guess": "Unknown",
                "country": "",
                "city": "",
                "asn": "",
                "org": "",
                "first_seen": None,
                "last_seen": None,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "dst_ports": set(),
                "src_ports": set(),
                "vendor": "",
                "is_router": False,
                "ttl": 0,
                "window_size": 0,
            }
        return self._hosts[ip]

    def process_packet(self, ts: float, buf: bytes, eth) -> None:
        if eth is None:
            return
        try:
            self._process(ts, buf, eth)
        except Exception:
            pass

    def _process(self, ts: float, buf: bytes, eth) -> None:
        src_mac = ""
        dst_mac = ""
        try:
            src_mac = ":".join("%02x" % b for b in eth.src)
            dst_mac = ":".join("%02x" % b for b in eth.dst)
        except Exception:
            pass

        # ARP
        if isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            try:
                spa = socket.inet_ntoa(arp.spa)
                sha = ":".join("%02x" % b for b in arp.sha)
                host = self._get_or_create(spa)
                if host["mac"] == "":
                    host["mac"] = sha
                if arp.op == dpkt.arp.ARP_OP_REPLY:
                    if spa in self._arp_table and self._arp_table[spa] != sha:
                        host["is_router"] = True
                    self._arp_table[spa] = sha
                    host["is_router"] = host.get("is_router", False)
            except Exception:
                pass
            return

        ip_layer = None
        if isinstance(eth.data, dpkt.ip.IP):
            ip_layer = eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip_layer = eth.data

        if ip_layer is None:
            return

        try:
            if isinstance(ip_layer, dpkt.ip.IP):
                src_ip = socket.inet_ntoa(ip_layer.src)
                dst_ip = socket.inet_ntoa(ip_layer.dst)
                ttl = ip_layer.ttl
            else:
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.dst)
                ttl = ip_layer.hlim
        except Exception:
            return

        pkt_len = len(buf)
        src_host = self._get_or_create(src_ip)
        dst_host = self._get_or_create(dst_ip)

        for host, mac in ((src_host, src_mac), (dst_host, dst_mac)):
            if host["mac"] == "" and mac:
                host["mac"] = mac
            if host["first_seen"] is None or ts < host["first_seen"]:
                host["first_seen"] = ts
            if host["last_seen"] is None or ts > host["last_seen"]:
                host["last_seen"] = ts

        src_host["bytes_sent"] += pkt_len
        src_host["ttl"] = ttl
        dst_host["bytes_recv"] += pkt_len

        transport = ip_layer.data
        src_port = dst_port = 0
        window = 0
        payload = b""

        if isinstance(transport, dpkt.tcp.TCP):
            src_port = transport.sport
            dst_port = transport.dport
            window = transport.win
            payload = bytes(transport.data)
            src_host["window_size"] = window
            src_host["os_guess"] = _ttl_window_os(ttl, window)
            # SNI
            if payload and payload[0] == 0x16:
                sni = _parse_tls_sni(payload)
                if sni:
                    dst_host["hostnames"].add(sni)
            # HTTP Host header
            if dst_port in (80, 8080, 8000, 8443) and payload:
                try:
                    text = payload.decode("utf-8", errors="ignore")
                    for line in text.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host_val = line[5:].strip().split(":")[0]
                            if host_val:
                                dst_host["hostnames"].add(host_val)
                            break
                except Exception:
                    pass

        elif isinstance(transport, dpkt.udp.UDP):
            src_port = transport.sport
            dst_port = transport.dport
            payload = bytes(transport.data)

        elif isinstance(transport, dpkt.icmp.ICMP):
            pass

        if src_port:
            src_host["src_ports"].add(src_port)
        if dst_port:
            src_host["dst_ports"].add(dst_port)

        # DNS
        if isinstance(transport, dpkt.udp.UDP) and (dst_port == 53 or src_port == 53):
            try:
                dns = dpkt.dns.DNS(payload)
                if dns.qr == dpkt.dns.DNS_R:
                    for rr in dns.an:
                        try:
                            name = rr.name
                            if rr.type == dpkt.dns.DNS_A:
                                resolved_ip = socket.inet_ntoa(rr.rdata)
                                h = self._get_or_create(resolved_ip)
                                h["hostnames"].add(name)
                            elif rr.type == dpkt.dns.DNS_AAAA:
                                resolved_ip = socket.inet_ntop(socket.AF_INET6, rr.rdata)
                                h = self._get_or_create(resolved_ip)
                                h["hostnames"].add(name)
                            elif rr.type == dpkt.dns.DNS_PTR:
                                ptr_name = rr.rdata if isinstance(rr.rdata, str) else rr.rdata.decode("utf-8", errors="ignore")
                                rev_ip = name.replace(".in-addr.arpa", "").split(".")
                                rev_ip.reverse()
                                rev_ip_str = ".".join(rev_ip)
                                if rev_ip_str in self._hosts:
                                    self._hosts[rev_ip_str]["hostnames"].add(ptr_name)
                        except Exception:
                            pass
            except Exception:
                pass

    @property
    def hosts(self) -> dict:
        return self._hosts

    def get_host(self, ip: str) -> dict:
        return self._hosts.get(ip)
