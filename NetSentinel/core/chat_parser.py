"""Parse AIM/OSCAR chat protocol on TCP port 5190."""
import struct
from collections import defaultdict


FLAP_HEADER = 0x2A
SNAC_FAMILY_ICBM = 0x0004
SNAC_SUBTYPE_ICBM_MSG = 0x0007


def _read_u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        return 0
    return struct.unpack_from("!H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from("!I", data, offset)[0]


def _parse_flap(data: bytes, pos: int):
    """Parse a FLAP frame starting at pos. Returns (channel, payload, next_pos) or None."""
    if pos + 6 > len(data):
        return None
    if data[pos] != FLAP_HEADER:
        return None
    channel = data[pos + 1]
    # seq = _read_u16(data, pos + 2)  # not needed
    dlen = _read_u16(data, pos + 4)
    end = pos + 6 + dlen
    if end > len(data):
        return None
    payload = data[pos + 6:end]
    return channel, payload, end


def _parse_snac(payload: bytes):
    """Parse SNAC header from FLAP channel 2 payload."""
    if len(payload) < 10:
        return None
    family = _read_u16(payload, 0)
    subtype = _read_u16(payload, 2)
    # flags = _read_u16(payload, 4)
    # request_id = _read_u32(payload, 6)
    data = payload[10:]
    return family, subtype, data


def _parse_tlv(data: bytes, offset: int):
    """Parse one TLV. Returns (type, value_bytes, next_offset)."""
    if offset + 4 > len(data):
        return None
    t = _read_u16(data, offset)
    l = _read_u16(data, offset + 2)
    end = offset + 4 + l
    if end > len(data):
        return None
    return t, data[offset + 4:end], end


def _parse_icbm_msg(data: bytes, direction: str):
    """Parse ICBM message SNAC (family 4, subtype 7). Returns (sender, receiver, text)."""
    offset = 8  # skip cookie (8 bytes)
    if offset + 2 > len(data):
        return None
    channel = _read_u16(data, offset)
    offset += 2

    # userinfo: sn_len(1) + sn + warning(2) + tlvcount(2) + tlvs
    if offset >= len(data):
        return None
    sn_len = data[offset]
    offset += 1
    if offset + sn_len > len(data):
        return None
    sender = data[offset:offset + sn_len].decode("ascii", errors="ignore")
    offset += sn_len
    if offset + 4 > len(data):
        return None
    # warning level (2) + tlv count (2)
    tlv_count = _read_u16(data, offset + 2)
    offset += 4
    for _ in range(tlv_count):
        result = _parse_tlv(data, offset)
        if result is None:
            break
        _, _, offset = result

    # Now parse message TLVs
    text = ""
    while offset < len(data):
        result = _parse_tlv(data, offset)
        if result is None:
            break
        t, v, offset = result
        if t == 0x0002:  # message TLV
            # skip 2-byte charset + 2-byte lang
            if len(v) > 4:
                text = v[4:].decode("utf-8", errors="ignore")

    return sender, text


class ChatParser:
    """Parse AIM/OSCAR chat streams on port 5190."""

    def __init__(self):
        self._conversations = defaultdict(list)  # frozenset({s,r}) -> [messages]

    def process_stream(self, stream_key, payload_bytes: bytes) -> None:
        if not payload_bytes:
            return

        # Determine direction context
        src_port = stream_key[1] if len(stream_key) >= 2 else 0
        dst_port = stream_key[3] if len(stream_key) >= 4 else 0
        if src_port != 5190 and dst_port != 5190:
            return

        direction = "fwd"
        pos = 0
        while pos < len(payload_bytes):
            result = _parse_flap(payload_bytes, pos)
            if result is None:
                pos += 1
                continue
            channel, payload, pos = result

            if channel != 2:
                continue

            snac = _parse_snac(payload)
            if snac is None:
                continue
            family, subtype, snac_data = snac

            if family == SNAC_FAMILY_ICBM and subtype == SNAC_SUBTYPE_ICBM_MSG:
                result2 = _parse_icbm_msg(snac_data, direction)
                if result2:
                    sender, text = result2
                    receiver = "unknown"
                    msg = {
                        "sender": sender,
                        "receiver": receiver,
                        "text": text,
                        "timestamp": None,
                        "direction": direction,
                    }
                    key = frozenset({sender, receiver})
                    self._conversations[key].append(msg)

    @property
    def conversations(self):
        return dict(self._conversations)
