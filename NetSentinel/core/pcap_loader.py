"""Single-pass PCAP/PCAPNG loader using dpkt."""
import struct
import dpkt


PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
PCAPNG_MAGIC = 0x0a0d0d0a


def _detect_format(filepath: str) -> str:
    with open(filepath, "rb") as f:
        magic = f.read(4)
    if len(magic) < 4:
        return "unknown"
    val = struct.unpack("<I", magic)[0]
    if val in (PCAP_MAGIC, PCAP_MAGIC_SWAPPED):
        return "pcap"
    val_be = struct.unpack(">I", magic)[0]
    if val_be == PCAPNG_MAGIC or val in (PCAPNG_MAGIC,):
        return "pcapng"
    # try big-endian pcap
    if val_be in (PCAP_MAGIC, PCAP_MAGIC_SWAPPED):
        return "pcap"
    return "pcap"


def _count_packets(filepath: str, fmt: str) -> int:
    count = 0
    try:
        with open(filepath, "rb") as f:
            if fmt == "pcapng":
                reader = dpkt.pcapng.Reader(f)
            else:
                reader = dpkt.pcap.Reader(f)
            for _ in reader:
                count += 1
    except Exception:
        pass
    return count


class PcapLoader:
    """Load PCAP/PCAPNG files and dispatch packets to registered callbacks."""

    def load(self, filepath: str, callbacks: dict) -> int:
        """
        Load file and dispatch packets.

        callbacks may contain:
          "packet"   -> callable(ts, raw_bytes, eth_frame)
          "progress" -> callable(packet_count)
        Returns total packet count processed.
        """
        fmt = _detect_format(filepath)
        total = _count_packets(filepath, fmt)

        packet_cb = callbacks.get("packet")
        progress_cb = callbacks.get("progress")

        count = 0
        with open(filepath, "rb") as f:
            if fmt == "pcapng":
                reader = dpkt.pcapng.Reader(f)
            else:
                reader = dpkt.pcap.Reader(f)

            for ts, buf in reader:
                eth = None
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    pass

                if packet_cb is not None:
                    try:
                        packet_cb(ts, buf, eth)
                    except Exception:
                        pass

                count += 1
                if progress_cb is not None and count % 1000 == 0:
                    try:
                        progress_cb(count)
                    except Exception:
                        pass

        if progress_cb is not None:
            try:
                progress_cb(count)
            except Exception:
                pass

        return count
