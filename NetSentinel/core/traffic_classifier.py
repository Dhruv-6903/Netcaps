"""Traffic protocol classifier by port and payload inspection."""

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "SMB", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "SYSLOG", 515: "LPD",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 1812: "RADIUS", 3306: "MySQL", 3389: "RDP",
    5190: "AIM", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    6881: "BitTorrent", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    8888: "HTTP-ALT", 9200: "Elasticsearch", 27017: "MongoDB",
}

PAYLOAD_SIGS = [
    (b"SSH-2.0", "SSH"),
    (b"SSH-1.", "SSH"),
    (b"220 ", "FTP/SMTP"),
    (b"EHLO", "SMTP"),
    (b"HELO", "SMTP"),
    (b"USER ", "FTP/POP3"),
    (b"HTTP/1.", "HTTP"),
    (b"GET /", "HTTP"),
    (b"POST /", "HTTP"),
    (b"HEAD /", "HTTP"),
    (b"PUT /", "HTTP"),
    (b"DELETE /", "HTTP"),
    (b"+OK", "POP3"),
    (b"* OK", "IMAP"),
    (b"\x16\x03", "TLS"),
    (b"\x16\x02", "TLS"),
]


class TrafficClassifier:
    """Classify traffic by port and payload."""

    def __init__(self):
        self._cache = {}

    def classify(self, src_port: int, dst_port: int, payload: bytes) -> str:
        cache_key = (src_port, dst_port, payload[:8] if payload else b"")
        if cache_key in self._cache:
            return self._cache[cache_key]

        label = self._do_classify(src_port, dst_port, payload)
        self._cache[cache_key] = label
        return label

    def _do_classify(self, src_port: int, dst_port: int, payload: bytes) -> str:
        # Check known ports first
        for port in (dst_port, src_port):
            if port in WELL_KNOWN_PORTS:
                return WELL_KNOWN_PORTS[port]

        # Payload inspection
        if payload:
            for sig, label in PAYLOAD_SIGS:
                if payload[:len(sig)] == sig or sig in payload[:64]:
                    return label

        return "Unknown"
