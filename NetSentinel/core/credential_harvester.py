"""Extract cleartext credentials from network traffic."""
import base64
import socket
import struct
from collections import defaultdict
import urllib.parse
import dpkt


FORM_USER_KEYS = {"username", "user", "login", "email", "uname", "usr"}
FORM_PASS_KEYS = {"password", "pass", "passwd", "pwd", "secret", "passphrase"}


def _decode_b64(s: str) -> str:
    try:
        return base64.b64decode(s.strip()).decode("utf-8", errors="ignore")
    except Exception:
        return s


def _strip_iac(data: bytes) -> bytes:
    """Strip Telnet IAC sequences."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xFF and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(data):
                i += 3
            else:
                i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


class CredentialHarvester:
    """Extract cleartext credentials from network streams."""

    def __init__(self):
        self._credentials = []
        self._streams = defaultdict(bytearray)  # key -> accumulated payload
        self._telnet_buf = defaultdict(bytearray)

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
        if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            return

        src_port = transport.sport
        dst_port = transport.dport
        payload = bytes(transport.data)
        if not payload:
            return

        # FTP
        if dst_port == 21 or src_port == 21:
            self._parse_ftp(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # Telnet
        if dst_port == 23 or src_port == 23:
            self._parse_telnet(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # HTTP
        if dst_port in (80, 8080, 8000, 3128):
            self._parse_http(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # SMTP AUTH
        if dst_port in (25, 465, 587):
            self._parse_smtp(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # POP3
        if dst_port in (110, 995):
            self._parse_pop3(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # IMAP
        if dst_port in (143, 993):
            self._parse_imap(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # LDAP
        if dst_port == 389:
            self._parse_ldap(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # SNMP
        if dst_port == 161 and isinstance(transport, dpkt.udp.UDP):
            self._parse_snmp(ts, payload, src_ip, dst_ip, src_port, dst_port)

        # RADIUS
        if dst_port == 1812 and isinstance(transport, dpkt.udp.UDP):
            self._parse_radius(ts, payload, src_ip, dst_ip, src_port, dst_port)

    def _add_cred(self, ts, proto, username, password, src_ip, dst_ip, src_port, dst_port, raw=""):
        self._credentials.append({
            "protocol": proto,
            "username": username,
            "password": password,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "timestamp": ts,
            "raw_context": raw[:200],
        })

    def _parse_ftp(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        text = payload.decode("utf-8", errors="ignore")
        key = (src_ip, dst_ip, src_port, dst_port)
        lines = text.replace("\r\n", "\n").split("\n")
        for line in lines:
            upper = line.strip().upper()
            if upper.startswith("USER "):
                self._streams[key + ("ftp_user",)] = bytearray(line.strip()[5:].encode())
            elif upper.startswith("PASS "):
                user_key = key + ("ftp_user",)
                username = self._streams.get(user_key, b"").decode("utf-8", errors="ignore") if isinstance(self._streams.get(user_key), (bytes, bytearray)) else str(self._streams.get(user_key, ""))
                password = line.strip()[5:]
                self._add_cred(ts, "FTP", username, password, src_ip, dst_ip, src_port, dst_port, line)

    def _parse_telnet(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        key = (src_ip, dst_ip, "telnet")
        cleaned = _strip_iac(payload)
        self._telnet_buf[key].extend(cleaned)
        text = self._telnet_buf[key].decode("utf-8", errors="ignore")
        if "\n" in text:
            lines = text.split("\n")
            self._telnet_buf[key] = bytearray(lines[-1].encode())
            for line in lines[:-1]:
                stripped = line.strip()
                if stripped:
                    # Try to parse user/pass from telnet stream heuristically
                    low = stripped.lower()
                    if "login:" in low or "username:" in low:
                        # store as pending
                        self._streams[key + ("user",)] = bytearray(stripped.encode())
                    elif "password:" in low:
                        user = self._streams.get(key + ("user",), b"")
                        self._add_cred(ts, "TELNET", user.decode("utf-8", errors="ignore") if isinstance(user, (bytes, bytearray)) else str(user), stripped, src_ip, dst_ip, src_port, dst_port, stripped)

    def _parse_http(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        text = payload.decode("utf-8", errors="ignore")
        headers_end = text.find("\r\n\r\n")
        header_block = text[:headers_end] if headers_end != -1 else text
        body = text[headers_end + 4:] if headers_end != -1 else ""

        # Basic Auth
        for line in header_block.split("\r\n"):
            if line.lower().startswith("authorization:"):
                val = line[14:].strip()
                if val.lower().startswith("basic "):
                    decoded = _decode_b64(val[6:])
                    if ":" in decoded:
                        u, p = decoded.split(":", 1)
                        self._add_cred(ts, "HTTP Basic Auth", u, p, src_ip, dst_ip, src_port, dst_port, line)
                elif val.lower().startswith("digest "):
                    params = {}
                    for part in val[7:].split(","):
                        part = part.strip()
                        if "=" in part:
                            k, v = part.split("=", 1)
                            params[k.strip()] = v.strip().strip('"')
                    if "username" in params:
                        self._add_cred(ts, "HTTP Digest Auth", params.get("username", ""), "", src_ip, dst_ip, src_port, dst_port, val[:200])

        # Form POST
        if "POST" in header_block[:10] and body:
            try:
                params = urllib.parse.parse_qs(body)
                username = ""
                password = ""
                for k, v in params.items():
                    kl = k.lower()
                    if kl in FORM_USER_KEYS:
                        username = v[0]
                    elif kl in FORM_PASS_KEYS:
                        password = v[0]
                if username or password:
                    self._add_cred(ts, "HTTP Form POST", username, password, src_ip, dst_ip, src_port, dst_port, body[:200])
            except Exception:
                pass

    def _parse_smtp(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        key = (src_ip, dst_ip, dst_port, "smtp")
        self._streams[key].extend(payload)
        text = self._streams[key].decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.strip().upper() == "AUTH LOGIN":
                # next line is b64 username
                if i + 1 < len(lines):
                    username = _decode_b64(lines[i + 1].strip())
                    password = ""
                    if i + 2 < len(lines):
                        password = _decode_b64(lines[i + 2].strip())
                    self._add_cred(ts, "SMTP AUTH LOGIN", username, password, src_ip, dst_ip, src_port, dst_port, line)
                    i += 3
                    continue
            elif line.strip().upper().startswith("AUTH PLAIN"):
                parts = line.strip().split(" ")
                if len(parts) > 2:
                    decoded = _decode_b64(parts[2])
                    parts2 = decoded.split("\x00")
                    if len(parts2) >= 3:
                        self._add_cred(ts, "SMTP AUTH PLAIN", parts2[1], parts2[2], src_ip, dst_ip, src_port, dst_port, line)
            i += 1
        # Keep only last 4KB
        if len(self._streams[key]) > 4096:
            self._streams[key] = bytearray(self._streams[key][-4096:])

    def _parse_pop3(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        text = payload.decode("utf-8", errors="ignore")
        key = (src_ip, dst_ip, dst_port, "pop3")
        lines = text.replace("\r\n", "\n").split("\n")
        for line in lines:
            stripped = line.strip()
            upper = stripped.upper()
            if upper.startswith("USER "):
                self._streams[key] = bytearray(stripped[5:].encode())
            elif upper.startswith("PASS "):
                user = self._streams.get(key, b"").decode("utf-8", errors="ignore") if isinstance(self._streams.get(key), (bytes, bytearray)) else ""
                self._add_cred(ts, "POP3", user, stripped[5:], src_ip, dst_ip, src_port, dst_port, stripped)

    def _parse_imap(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        text = payload.decode("utf-8", errors="ignore")
        for line in text.replace("\r\n", "\n").split("\n"):
            stripped = line.strip()
            upper = stripped.upper()
            if " LOGIN " in upper:
                parts = stripped.split()
                if len(parts) >= 4:
                    username = parts[2].strip('"')
                    password = parts[3].strip('"')
                    self._add_cred(ts, "IMAP LOGIN", username, password, src_ip, dst_ip, src_port, dst_port, stripped)

    def _parse_ldap(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        # LDAP BindRequest (simplified BER parse)
        # LDAP message: 30 <len> 02 01 <msgid> 60 <len> 02 01 03 04 <len> <dn> 80 <len> <password>
        try:
            if len(payload) < 10:
                return
            if payload[0] != 0x30:
                return
            # Skip outer sequence header
            offset = 2
            if payload[1] & 0x80:
                extra = payload[1] & 0x7F
                offset += extra
            # Integer (message ID)
            if payload[offset] != 0x02:
                return
            mid_len = payload[offset + 1]
            offset += 2 + mid_len
            # BindRequest
            if payload[offset] != 0x60:
                return
            offset += 2
            if payload[offset + 1] & 0x80:
                offset += payload[offset + 1] & 0x7F
            # version
            if payload[offset] != 0x02:
                return
            ver_len = payload[offset + 1]
            offset += 2 + ver_len
            # DN (OctetString)
            if payload[offset] != 0x04:
                return
            dn_len = payload[offset + 1]
            offset += 2
            dn = payload[offset:offset + dn_len].decode("utf-8", errors="ignore")
            offset += dn_len
            # Simple auth [0] or SASL [3]
            if offset < len(payload) and payload[offset] == 0x80:
                pw_len = payload[offset + 1]
                offset += 2
                password = payload[offset:offset + pw_len].decode("utf-8", errors="ignore")
                self._add_cred(ts, "LDAP Bind", dn, password, src_ip, dst_ip, src_port, dst_port, "")
        except Exception:
            pass

    def _parse_snmp(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        # Extract SNMP community string (v1/v2c)
        # SEQUENCE { INTEGER version, OCTET_STRING community, ... }
        try:
            if len(payload) < 6 or payload[0] != 0x30:
                return
            offset = 2
            if payload[1] & 0x80:
                offset += payload[1] & 0x7F
            if payload[offset] != 0x02:
                return
            ver_len = payload[offset + 1]
            offset += 2 + ver_len
            if payload[offset] != 0x04:
                return
            community_len = payload[offset + 1]
            offset += 2
            community = payload[offset:offset + community_len].decode("utf-8", errors="ignore")
            self._add_cred(ts, "SNMP Community", "", community, src_ip, dst_ip, src_port, dst_port, "")
        except Exception:
            pass

    def _parse_radius(self, ts, payload, src_ip, dst_ip, src_port, dst_port):
        # RADIUS Access-Request (code=1) with User-Name attribute (type=1)
        try:
            if len(payload) < 20:
                return
            code = payload[0]
            if code != 1:  # Access-Request
                return
            pkt_len = struct.unpack("!H", payload[2:4])[0]
            offset = 20
            while offset + 2 <= min(pkt_len, len(payload)):
                attr_type = payload[offset]
                attr_len = payload[offset + 1]
                if attr_len < 2:
                    break
                attr_val = payload[offset + 2:offset + attr_len]
                if attr_type == 1:  # User-Name
                    username = attr_val.decode("utf-8", errors="ignore")
                    self._add_cred(ts, "RADIUS", username, "", src_ip, dst_ip, src_port, dst_port, "")
                offset += attr_len
        except Exception:
            pass

    @property
    def credentials(self):
        return self._credentials
