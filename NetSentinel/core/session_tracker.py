"""Track TCP/UDP sessions by 5-tuple."""
import hashlib
import socket
from collections import defaultdict
import dpkt


def _make_key(src_ip, src_port, dst_ip, dst_port, proto):
    """Normalize direction: lower IP:port first."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a > b:
        a, b = b, a
    return (a[0], a[1], b[0], b[1], proto)


def _session_id(key):
    return hashlib.md5(str(key).encode()).hexdigest()[:16]


class SessionTracker:
    """Track TCP/UDP sessions."""

    UDP_TIMEOUT = 30.0
    MAX_PAYLOAD = 10 * 1024 * 1024  # 10MB

    def __init__(self):
        self._sessions = {}   # key -> session dict
        self._udp_last = {}   # key -> last_ts

    def _get_or_create(self, key, src_ip, src_port, dst_ip, dst_port, proto, ts):
        if key not in self._sessions:
            self._sessions[key] = {
                "session_id": _session_id(key),
                "src_ip": key[0],
                "src_port": key[1],
                "dst_ip": key[2],
                "dst_port": key[3],
                "protocol": proto,
                "app_label": "",
                "start_time": ts,
                "end_time": ts,
                "duration": 0.0,
                "bytes_src_to_dst": 0,
                "bytes_dst_to_src": 0,
                "packet_count_fwd": 0,
                "packet_count_bwd": 0,
                "tcp_flags": set(),
                "state": "INIT",
                "payload_fwd": bytearray(),
                "payload_bwd": bytearray(),
            }
        return self._sessions[key]

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
            proto_name = "TCP" if isinstance(ip_layer.data, dpkt.tcp.TCP) else \
                         "UDP" if isinstance(ip_layer.data, dpkt.udp.UDP) else \
                         "ICMP" if isinstance(ip_layer.data, dpkt.icmp.ICMP) else "OTHER"
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip_layer = eth.data
            proto_name = "TCP" if isinstance(ip_layer.data, dpkt.tcp.TCP) else \
                         "UDP" if isinstance(ip_layer.data, dpkt.udp.UDP) else "OTHER"
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

        transport = ip_layer.data
        pkt_len = len(buf)

        if isinstance(transport, dpkt.tcp.TCP):
            src_port = transport.sport
            dst_port = transport.dport
            flags = transport.flags
            payload = bytes(transport.data)
            key = _make_key(src_ip, src_port, dst_ip, dst_port, "TCP")
            sess = self._get_or_create(key, src_ip, src_port, dst_ip, dst_port, "TCP", ts)

            # Determine direction
            fwd = (src_ip == key[0] and src_port == key[1])

            flag_names = []
            if flags & dpkt.tcp.TH_SYN:
                flag_names.append("SYN")
                sess["state"] = "INIT"
            if flags & dpkt.tcp.TH_ACK:
                flag_names.append("ACK")
                if sess["state"] == "INIT":
                    sess["state"] = "ESTABLISHED"
            if flags & dpkt.tcp.TH_FIN:
                flag_names.append("FIN")
                sess["state"] = "CLOSED"
            if flags & dpkt.tcp.TH_RST:
                flag_names.append("RST")
                sess["state"] = "CLOSED"

            sess["tcp_flags"].update(flag_names)
            sess["end_time"] = ts
            sess["duration"] = ts - sess["start_time"]

            if fwd:
                sess["bytes_src_to_dst"] += pkt_len
                sess["packet_count_fwd"] += 1
                if payload and len(sess["payload_fwd"]) < self.MAX_PAYLOAD:
                    sess["payload_fwd"].extend(payload[:self.MAX_PAYLOAD - len(sess["payload_fwd"])])
            else:
                sess["bytes_dst_to_src"] += pkt_len
                sess["packet_count_bwd"] += 1
                if payload and len(sess["payload_bwd"]) < self.MAX_PAYLOAD:
                    sess["payload_bwd"].extend(payload[:self.MAX_PAYLOAD - len(sess["payload_bwd"])])

        elif isinstance(transport, dpkt.udp.UDP):
            src_port = transport.sport
            dst_port = transport.dport
            payload = bytes(transport.data)
            key = _make_key(src_ip, src_port, dst_ip, dst_port, "UDP")

            # UDP inactivity timeout
            last = self._udp_last.get(key)
            if last is not None and (ts - last) > self.UDP_TIMEOUT:
                if key in self._sessions:
                    self._sessions[key]["state"] = "CLOSED"
                    del self._sessions[key]

            sess = self._get_or_create(key, src_ip, src_port, dst_ip, dst_port, "UDP", ts)
            self._udp_last[key] = ts

            fwd = (src_ip == key[0] and src_port == key[1])
            sess["end_time"] = ts
            sess["duration"] = ts - sess["start_time"]
            sess["state"] = "ESTABLISHED"

            if fwd:
                sess["bytes_src_to_dst"] += pkt_len
                sess["packet_count_fwd"] += 1
                if payload and len(sess["payload_fwd"]) < self.MAX_PAYLOAD:
                    sess["payload_fwd"].extend(payload[:self.MAX_PAYLOAD - len(sess["payload_fwd"])])
            else:
                sess["bytes_dst_to_src"] += pkt_len
                sess["packet_count_bwd"] += 1
                if payload and len(sess["payload_bwd"]) < self.MAX_PAYLOAD:
                    sess["payload_bwd"].extend(payload[:self.MAX_PAYLOAD - len(sess["payload_bwd"])])

    @property
    def sessions(self):
        return list(self._sessions.values())
