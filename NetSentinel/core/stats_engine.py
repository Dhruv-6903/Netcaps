"""Traffic statistics engine."""
import socket
from collections import defaultdict, deque
import dpkt


class StatsEngine:
    """Collect and track traffic statistics."""

    def __init__(self):
        self._total_packets = 0
        self._total_bytes = 0
        self._protocol_dist = defaultdict(int)
        self._src_ip_counts = defaultdict(int)
        self._dst_ip_counts = defaultdict(int)
        self._dst_port_counts = defaultdict(int)
        self._packet_sizes = []
        self._bw_history = deque(maxlen=3600)  # up to 1h at 1s resolution
        self._current_window_start = None
        self._current_window_bytes = 0
        self._packets_per_sec_buf = deque(maxlen=60)
        self._pps_window_start = None
        self._pps_count = 0

    def process_packet(self, ts: float, buf: bytes, eth) -> None:
        self._total_packets += 1
        pkt_len = len(buf)
        self._total_bytes += pkt_len
        self._packet_sizes.append(pkt_len)

        # Bandwidth per second
        if self._current_window_start is None:
            self._current_window_start = ts
        if ts - self._current_window_start >= 1.0:
            self._bw_history.append((self._current_window_start, self._current_window_bytes))
            self._current_window_start = ts
            self._current_window_bytes = 0
        self._current_window_bytes += pkt_len

        # PPS
        if self._pps_window_start is None:
            self._pps_window_start = ts
        if ts - self._pps_window_start >= 1.0:
            self._packets_per_sec_buf.append(self._pps_count)
            self._pps_window_start = ts
            self._pps_count = 0
        self._pps_count += 1

        if eth is None:
            self._protocol_dist["other"] += 1
            return

        ip_layer = None
        proto_name = "other"

        if isinstance(eth.data, dpkt.ip.IP):
            ip_layer = eth.data
            transport = ip_layer.data
            if isinstance(transport, dpkt.tcp.TCP):
                proto_name = "TCP"
            elif isinstance(transport, dpkt.udp.UDP):
                proto_name = "UDP"
            elif isinstance(transport, dpkt.icmp.ICMP):
                proto_name = "ICMP"
            else:
                proto_name = "other"
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip_layer = eth.data
            proto_name = "IPv6"
        elif isinstance(eth.data, dpkt.arp.ARP):
            proto_name = "ARP"
        else:
            proto_name = "other"

        self._protocol_dist[proto_name] += 1

        if ip_layer is not None:
            try:
                if isinstance(ip_layer, dpkt.ip.IP):
                    src_ip = socket.inet_ntoa(ip_layer.src)
                    dst_ip = socket.inet_ntoa(ip_layer.dst)
                else:
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip_layer.dst)
                self._src_ip_counts[src_ip] += 1
                self._dst_ip_counts[dst_ip] += 1

                transport = ip_layer.data
                if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    self._dst_port_counts[transport.dport] += 1
            except Exception:
                pass

    @property
    def stats(self) -> dict:
        sizes = self._packet_sizes
        avg_size = sum(sizes) / len(sizes) if sizes else 0
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        pps = list(self._packets_per_sec_buf)
        avg_pps = sum(pps) / len(pps) if pps else 0

        top_src = sorted(self._src_ip_counts.items(), key=lambda x: -x[1])[:20]
        top_dst = sorted(self._dst_ip_counts.items(), key=lambda x: -x[1])[:20]
        top_ports = sorted(self._dst_port_counts.items(), key=lambda x: -x[1])[:20]

        bw = list(self._bw_history)
        avg_bw = sum(b for _, b in bw) / len(bw) if bw else 0

        return {
            "total_packets": self._total_packets,
            "total_bytes": self._total_bytes,
            "packets_per_sec": avg_pps,
            "protocol_distribution": dict(self._protocol_dist),
            "top_src_ips": top_src,
            "top_dst_ips": top_dst,
            "top_dst_ports": top_ports,
            "bytes_per_sec": avg_bw,
            "avg_packet_size": avg_size,
            "min_packet_size": min_size,
            "max_packet_size": max_size,
        }

    @property
    def bandwidth_history(self):
        return list(self._bw_history)
