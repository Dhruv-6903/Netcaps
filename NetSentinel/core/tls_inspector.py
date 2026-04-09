"""TLS inspection: version, JA3/JA3S, cipher strength, certificate parsing."""
import hashlib
import socket
import struct
from collections import defaultdict
import dpkt


WEAK_CIPHERS = {
    0x0000,  # TLS_NULL_WITH_NULL_NULL
    0x0001,  # TLS_RSA_WITH_NULL_MD5
    0x0002,  # TLS_RSA_WITH_NULL_SHA
    0x0004,  # TLS_RSA_WITH_RC4_128_MD5
    0x0005,  # TLS_RSA_WITH_RC4_128_SHA
    0x000A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x0009,  # TLS_RSA_WITH_DES_CBC_SHA
    0xC011,  # TLS_ECDHE_RSA_WITH_RC4_128_SHA
    0x0062,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0063,  # TLS_DHE_DSS_WITH_DES_CBC_SHA
}

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0300: "SSL 3.0",
}

OUTDATED_VERSIONS = {0x0301, 0x0302, 0x0300}


def _u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        return 0
    return struct.unpack_from("!H", data, off)[0]


def _u8(data: bytes, off: int) -> int:
    if off >= len(data):
        return 0
    return data[off]


def _parse_client_hello(payload: bytes):
    """Parse TLS ClientHello. Returns dict with ja3 components or None."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        rec_ver = _u16(payload, 1)
        rec_len = _u16(payload, 3)
        if len(payload) < 5 + rec_len:
            return None
        hs = payload[5:]
        if _u8(hs, 0) != 0x01:  # Not ClientHello
            return None
        hs_len = (_u8(hs, 1) << 16) | _u16(hs, 2)
        offset = 4
        client_ver = _u16(hs, offset)
        offset += 2 + 32  # version + random
        # session id
        sess_len = _u8(hs, offset)
        offset += 1 + sess_len
        # cipher suites
        cs_len = _u16(hs, offset)
        offset += 2
        ciphers = []
        for i in range(cs_len // 2):
            c = _u16(hs, offset + i * 2)
            if c != 0x00FF:  # skip SCSV
                ciphers.append(c)
        offset += cs_len
        # compression
        comp_len = _u8(hs, offset)
        offset += 1 + comp_len
        # extensions
        if offset + 2 > len(hs):
            return {"version": client_ver, "ciphers": ciphers, "extensions": [], "curves": [], "point_formats": []}
        ext_total = _u16(hs, offset)
        offset += 2
        end = offset + ext_total
        extensions = []
        curves = []
        point_formats = []
        sni = ""
        while offset + 4 <= end and offset + 4 <= len(hs):
            ext_type = _u16(hs, offset)
            ext_len = _u16(hs, offset + 2)
            offset += 4
            ext_data = hs[offset:offset + ext_len]
            extensions.append(ext_type)
            if ext_type == 0x0000 and len(ext_data) >= 5:
                name_len = _u16(ext_data, 2)
                sni = ext_data[5:5 + name_len].decode("utf-8", errors="ignore")
            elif ext_type == 0x000A and len(ext_data) >= 2:
                cl = _u16(ext_data, 0)
                for i in range(cl // 2):
                    curves.append(_u16(ext_data, 2 + i * 2))
            elif ext_type == 0x000B and len(ext_data) >= 1:
                pfl = _u8(ext_data, 0)
                for i in range(pfl):
                    point_formats.append(_u8(ext_data, 1 + i))
            offset += ext_len

        return {
            "version": client_ver,
            "ciphers": ciphers,
            "extensions": extensions,
            "curves": curves,
            "point_formats": point_formats,
            "sni": sni,
        }
    except Exception:
        return None


def _parse_server_hello(payload: bytes):
    """Parse TLS ServerHello. Returns dict with ja3s components."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        rec_len = _u16(payload, 3)
        hs = payload[5:]
        if _u8(hs, 0) != 0x02:  # Not ServerHello
            return None
        offset = 4
        server_ver = _u16(hs, offset)
        offset += 2 + 32  # version + random
        sess_len = _u8(hs, offset)
        offset += 1 + sess_len
        cipher = _u16(hs, offset)
        offset += 2 + 1  # cipher + compression
        extensions = []
        if offset + 2 <= len(hs):
            ext_total = _u16(hs, offset)
            offset += 2
            end = offset + ext_total
            while offset + 4 <= end and offset + 4 <= len(hs):
                ext_type = _u16(hs, offset)
                ext_len = _u16(hs, offset + 2)
                offset += 4 + ext_len
                extensions.append(ext_type)
        return {"version": server_ver, "cipher": cipher, "extensions": extensions}
    except Exception:
        return None


def _build_ja3(ch: dict) -> str:
    ver = str(ch["version"])
    ciphers = "-".join(str(c) for c in ch["ciphers"])
    exts = "-".join(str(e) for e in ch["extensions"])
    curves = "-".join(str(c) for c in ch["curves"])
    points = "-".join(str(p) for p in ch["point_formats"])
    return f"{ver},{ciphers},{exts},{curves},{points}"


def _build_ja3s(sh: dict) -> str:
    ver = str(sh["version"])
    cipher = str(sh["cipher"])
    exts = "-".join(str(e) for e in sh["extensions"])
    return f"{ver},{cipher},{exts}"


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


class TlsInspector:
    """Inspect TLS sessions for version, cipher strength, JA3/JA3S."""

    def __init__(self):
        self._sessions = {}  # flow_key -> session dict

    def _get_key(self, src_ip, src_port, dst_ip, dst_port):
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a > b:
            a, b = b, a
        return a + b

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
        payload = bytes(tcp.data)
        if not payload or payload[0] != 0x16:
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

        src_port = tcp.sport
        dst_port = tcp.dport
        key = self._get_key(src_ip, src_port, dst_ip, dst_port)

        if key not in self._sessions:
            self._sessions[key] = {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "timestamp": ts,
                "tls_version": "",
                "tls_version_raw": 0,
                "is_outdated": False,
                "ja3": "",
                "ja3_hash": "",
                "ja3s": "",
                "ja3s_hash": "",
                "weak_ciphers": [],
                "sni": "",
                "cert": {},
            }

        sess = self._sessions[key]

        # Detect record type
        rec_type = payload[0]
        rec_ver_raw = struct.unpack_from("!H", payload, 1)[0] if len(payload) >= 3 else 0
        tls_ver = TLS_VERSIONS.get(rec_ver_raw, f"Unknown (0x{rec_ver_raw:04x})")

        if not sess["tls_version"]:
            sess["tls_version"] = tls_ver
            sess["tls_version_raw"] = rec_ver_raw
            sess["is_outdated"] = rec_ver_raw in OUTDATED_VERSIONS

        if len(payload) >= 6:
            hs_type = payload[5] if len(payload) > 5 else 0
            if hs_type == 0x01 and not sess["ja3"]:
                ch = _parse_client_hello(payload)
                if ch:
                    ja3_str = _build_ja3(ch)
                    sess["ja3"] = ja3_str
                    sess["ja3_hash"] = _md5(ja3_str)
                    sess["sni"] = ch.get("sni", "")
                    weak = [c for c in ch.get("ciphers", []) if c in WEAK_CIPHERS]
                    sess["weak_ciphers"] = [f"0x{c:04x}" for c in weak]

            elif hs_type == 0x02 and not sess["ja3s"]:
                sh = _parse_server_hello(payload)
                if sh:
                    ja3s_str = _build_ja3s(sh)
                    sess["ja3s"] = ja3s_str
                    sess["ja3s_hash"] = _md5(ja3s_str)
                    if sh["cipher"] in WEAK_CIPHERS:
                        if f"0x{sh['cipher']:04x}" not in sess["weak_ciphers"]:
                            sess["weak_ciphers"].append(f"0x{sh['cipher']:04x}")

    @property
    def tls_sessions(self):
        return list(self._sessions.values())
