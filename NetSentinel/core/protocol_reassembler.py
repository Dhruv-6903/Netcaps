"""TCP stream reassembly."""
import socket
from collections import defaultdict
import dpkt


MAX_STREAM = 10 * 1024 * 1024  # 10MB


def _make_key(src_ip, src_port, dst_ip, dst_port):
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a > b:
        a, b = b, a
    return (a[0], a[1], b[0], b[1], "TCP")


class ProtocolReassembler:
    """Reassemble TCP streams and dispatch to handlers."""

    def __init__(self):
        self._streams = {}  # key -> {"fwd": bytearray, "bwd": bytearray, "closed": bool}
        self._handlers = []

    def register_handler(self, handler_fn):
        self._handlers.append(handler_fn)

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

        if not isinstance(ip_layer.data, dpkt.tcp.TCP):
            return

        tcp = ip_layer.data
        try:
            if isinstance(ip_layer, dpkt.ip.IP):
                src_ip = socket.inet_ntoa(ip_layer.src)
                dst_ip = socket.inet_ntoa(ip_layer.dst)
            else:
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.dst)
        except Exception:
            return

        src_port = tcp.sport
        dst_port = tcp.dport
        key = _make_key(src_ip, src_port, dst_ip, dst_port)
        flags = tcp.flags
        payload = bytes(tcp.data)

        if flags & dpkt.tcp.TH_SYN and not (flags & dpkt.tcp.TH_ACK):
            if key not in self._streams:
                self._streams[key] = {"fwd": bytearray(), "bwd": bytearray(), "closed": False}

        if key not in self._streams:
            self._streams[key] = {"fwd": bytearray(), "bwd": bytearray(), "closed": False}

        stream = self._streams[key]
        fwd = (src_ip == key[0] and src_port == key[1])
        direction = "fwd" if fwd else "bwd"

        if payload:
            buf_ref = stream[direction]
            remaining = MAX_STREAM - len(buf_ref)
            if remaining > 0:
                buf_ref.extend(payload[:remaining])

            # Flush if cap exceeded
            if len(buf_ref) >= MAX_STREAM:
                self._dispatch(key, bytes(buf_ref), direction)
                buf_ref.clear()

        if flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
            self._close_stream(key)

    def _dispatch(self, key, payload_bytes, direction):
        for handler in self._handlers:
            try:
                handler(key, payload_bytes, direction)
            except Exception:
                pass

    def _close_stream(self, key):
        if key not in self._streams:
            return
        stream = self._streams[key]
        if stream.get("closed"):
            return
        stream["closed"] = True
        for direction in ("fwd", "bwd"):
            if stream[direction]:
                self._dispatch(key, bytes(stream[direction]), direction)
        del self._streams[key]
