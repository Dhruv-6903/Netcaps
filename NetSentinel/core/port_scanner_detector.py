"""Detect port scanning activity."""
import socket
from collections import defaultdict
from datetime import datetime
import dpkt


def _ts_str(ts):
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


class PortScannerDetector:
    """Detect horizontal and vertical port scanning."""

    HORIZONTAL_THRESHOLD = 20   # >20 distinct ports from one src to one dst in 5s
    VERTICAL_THRESHOLD = 10     # same port on >10 distinct dst IPs from one src in 10s
    HORIZONTAL_WINDOW = 5.0
    VERTICAL_WINDOW = 10.0

    def __init__(self):
        self._scan_events = []
        # src_ip -> dst_ip -> [(port, ts)]
        self._horizontal = defaultdict(lambda: defaultdict(list))
        # src_ip -> port -> [(dst_ip, ts)]
        self._vertical = defaultdict(lambda: defaultdict(list))
        self._reported = set()  # avoid duplicate alerts

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

        transport = ip_layer.data
        if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
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

        dst_port = transport.dport

        # Track for horizontal scan
        self._horizontal[src_ip][dst_ip].append((dst_port, ts))
        # Track for vertical scan
        self._vertical[src_ip][dst_port].append((dst_ip, ts))

        # Check horizontal scan
        h_key = (src_ip, dst_ip, "H")
        if h_key not in self._reported:
            entries = self._horizontal[src_ip][dst_ip]
            for i, (port_i, t_i) in enumerate(entries):
                window_entries = [(p, t) for p, t in entries if t_i <= t <= t_i + self.HORIZONTAL_WINDOW]
                distinct_ports = {p for p, _ in window_entries}
                if len(distinct_ports) > self.HORIZONTAL_THRESHOLD:
                    self._scan_events.append({
                        "type": "horizontal",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": None,
                        "distinct_count": len(distinct_ports),
                        "window_sec": self.HORIZONTAL_WINDOW,
                        "timestamp": t_i,
                        "timestamp_str": _ts_str(t_i),
                        "description": f"{src_ip} scanned {len(distinct_ports)} ports on {dst_ip} in {self.HORIZONTAL_WINDOW}s",
                    })
                    self._reported.add(h_key)
                    break

        # Check vertical scan
        v_key = (src_ip, dst_port, "V")
        if v_key not in self._reported:
            entries = self._vertical[src_ip][dst_port]
            for i, (dst_i, t_i) in enumerate(entries):
                window_entries = [(d, t) for d, t in entries if t_i <= t <= t_i + self.VERTICAL_WINDOW]
                distinct_dsts = {d for d, _ in window_entries}
                if len(distinct_dsts) > self.VERTICAL_THRESHOLD:
                    self._scan_events.append({
                        "type": "vertical",
                        "src_ip": src_ip,
                        "dst_ip": None,
                        "port": dst_port,
                        "distinct_count": len(distinct_dsts),
                        "window_sec": self.VERTICAL_WINDOW,
                        "timestamp": t_i,
                        "timestamp_str": _ts_str(t_i),
                        "description": f"{src_ip} scanned port {dst_port} on {len(distinct_dsts)} hosts in {self.VERTICAL_WINDOW}s",
                    })
                    self._reported.add(v_key)
                    break

    @property
    def scan_events(self):
        return self._scan_events
