"""Parse email protocols: SMTP, POP3, IMAP."""
import email.parser
import re
from urllib.parse import urlparse


KEYWORDS = [
    "password", "secret", "account", "meeting", "location", "address",
    "money", "transfer", "urgent", "confidential", "wire", "bitcoin",
    "credential", "login", "payroll",
]

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


def _extract_text_html(msg) -> tuple:
    body_text = ""
    body_html = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "text/plain" and not body_text:
            try:
                body_text = part.get_payload(decode=True).decode("utf-8", errors="ignore")
            except Exception:
                pass
        elif ct == "text/html" and not body_html:
            try:
                body_html = part.get_payload(decode=True).decode("utf-8", errors="ignore")
            except Exception:
                pass
    return body_text, body_html


class EmailParser:
    """Detect and parse SMTP/POP3/IMAP email traffic."""

    def __init__(self):
        self._emails = []
        self._streams = {}  # key -> bytearray

    def process_stream(self, stream_key, payload_bytes: bytes, direction: str) -> None:
        if not payload_bytes:
            return
        try:
            port = stream_key[3] if len(stream_key) >= 4 else 0
            if port in (25, 465, 587):
                self._parse_smtp(stream_key, payload_bytes)
            elif port in (110, 995):
                self._parse_pop3(stream_key, payload_bytes)
            elif port in (143, 993):
                self._parse_imap(stream_key, payload_bytes)
            else:
                # Try all
                self._parse_smtp(stream_key, payload_bytes)
        except Exception:
            pass

    def _parse_smtp(self, stream_key, payload: bytes) -> None:
        text = payload.decode("latin-1", errors="ignore")
        # Find DATA section
        data_idx = text.upper().find("\r\nDATA\r\n")
        if data_idx == -1:
            data_idx = text.upper().find("\nDATA\n")
        if data_idx == -1:
            return
        email_start = data_idx + 8
        # End marker: \r\n.\r\n
        end_idx = text.find("\r\n.\r\n", email_start)
        if end_idx == -1:
            email_text = text[email_start:]
        else:
            email_text = text[email_start:end_idx]
        self._parse_message(email_text.encode("latin-1", errors="ignore"), stream_key)

    def _parse_pop3(self, stream_key, payload: bytes) -> None:
        text = payload.decode("latin-1", errors="ignore")
        # After +OK <n> octets
        m = re.search(r'\+OK \d+ octets?\r?\n', text, re.IGNORECASE)
        if not m:
            return
        email_text = text[m.end():]
        end_idx = email_text.find("\r\n.\r\n")
        if end_idx != -1:
            email_text = email_text[:end_idx]
        self._parse_message(email_text.encode("latin-1", errors="ignore"), stream_key)

    def _parse_imap(self, stream_key, payload: bytes) -> None:
        text = payload.decode("latin-1", errors="ignore")
        # FETCH BODY response
        m = re.search(r'\* \d+ FETCH \(BODY\[TEXT\] \{\d+\}\r?\n', text, re.IGNORECASE)
        if not m:
            m = re.search(r'\* \d+ FETCH \(RFC822 \{\d+\}\r?\n', text, re.IGNORECASE)
        if not m:
            return
        email_text = text[m.end():]
        self._parse_message(email_text.encode("latin-1", errors="ignore"), stream_key)

    def _parse_message(self, raw: bytes, stream_key) -> None:
        if not raw.strip():
            return
        try:
            parser = email.parser.BytesParser()
            msg = parser.parsebytes(raw)
        except Exception:
            return

        from_addr = msg.get("From", "")
        to_header = msg.get("To", "")
        cc_header = msg.get("Cc", "")
        subject = msg.get("Subject", "")
        date = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")
        x_orig_ip = msg.get("X-Originating-IP", "")

        to_list = [a.strip() for a in to_header.split(",") if a.strip()]
        cc_list = [a.strip() for a in cc_header.split(",") if a.strip()]

        # Received chain
        received_chain = msg.get_all("Received", [])

        body_text, body_html = _extract_text_html(msg)
        full_body = body_text + body_html

        # Extract URLs, IPs, emails
        embedded_urls = URL_RE.findall(full_body)
        embedded_ips = IP_RE.findall(full_body)
        embedded_emails = EMAIL_RE.findall(full_body)

        # Keyword scan
        found_keywords = [kw for kw in KEYWORDS if kw.lower() in full_body.lower()]

        # Attachments
        attachments = []
        for part in msg.walk():
            cd = part.get("Content-Disposition", "")
            if "attachment" in cd.lower():
                fname = part.get_filename() or ""
                payload_data = part.get_payload(decode=True)
                attachments.append({
                    "filename": fname,
                    "mime_type": part.get_content_type(),
                    "size": len(payload_data) if payload_data else 0,
                })

        src_ip = str(stream_key[0]) if len(stream_key) >= 1 else ""

        self._emails.append({
            "message_id": message_id,
            "from_addr": from_addr,
            "to_list": to_list,
            "cc_list": cc_list,
            "subject": subject,
            "date": date,
            "body_text": body_text[:2048],
            "body_html": body_html[:2048],
            "attachments": attachments,
            "x_originating_ip": x_orig_ip,
            "received_chain": received_chain,
            "embedded_urls": embedded_urls,
            "embedded_ips": embedded_ips,
            "embedded_emails": embedded_emails,
            "keywords_found": found_keywords,
            "src_ip": src_ip,
        })

    @property
    def emails(self):
        return self._emails
