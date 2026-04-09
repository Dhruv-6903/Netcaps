"""Live packet capture using scapy AsyncSniffer."""
import collections
import threading


class LiveCapture:
    """Live packet capture via scapy AsyncSniffer."""

    BUFFER_SIZE = 100

    def __init__(self):
        self._sniffer = None
        self._callback = None
        self._buffer = collections.deque(maxlen=self.BUFFER_SIZE)
        self._running = False
        self._lock = threading.Lock()

    def set_packet_callback(self, cb) -> None:
        self._callback = cb

    def start(self, interface: str, bpf_filter: str = "") -> None:
        from scapy.all import AsyncSniffer
        if self._running:
            return
        self._running = True
        kwargs = {
            "iface": interface,
            "prn": self._on_packet,
            "store": False,
        }
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def _on_packet(self, pkt) -> None:
        try:
            raw = bytes(pkt)
            with self._lock:
                self._buffer.append(raw)
            if self._callback is not None:
                self._callback(raw)
        except Exception:
            pass

    def stop(self) -> None:
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    def get_buffer(self):
        with self._lock:
            return list(self._buffer)
