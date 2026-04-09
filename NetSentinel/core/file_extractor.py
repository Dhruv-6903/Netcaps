"""Extract files from HTTP, FTP, SMTP streams."""
import gzip
import hashlib
import io
import os
import re
import zlib
import email.parser
from collections import defaultdict
from pathlib import Path

try:
    import magic as _magic
    _MAGIC_AVAILABLE = True
except Exception:
    _MAGIC_AVAILABLE = False

from config import settings

# Magic bytes for file carving
FILE_SIGNATURES = [
    (b"\x25\x50\x44\x46", "pdf", ".pdf"),
    (b"\xff\xd8\xff", "jpeg", ".jpg"),
    (b"\x89\x50\x4e\x47", "png", ".png"),
    (b"\x50\x4b\x03\x04", "zip", ".zip"),
    (b"\x4d\x5a", "exe", ".exe"),
    (b"\xd0\xcf\x11\xe0", "ole", ".doc"),
]

_COUNTER = defaultdict(int)


def _safe_filename(name: str) -> str:
    name = re.sub(r"[^\w\-_\. ]", "_", name)
    return name[:120] if name else "extracted_file"


def _unique_path(outdir: str, filename: str) -> str:
    path = os.path.join(outdir, filename)
    base, ext = os.path.splitext(filename)
    n = 1
    while os.path.exists(path):
        path = os.path.join(outdir, f"{base}_{n}{ext}")
        n += 1
    return path


def _hash_bytes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _detect_mime(data: bytes, filename: str = "") -> str:
    if _MAGIC_AVAILABLE:
        try:
            return _magic.from_buffer(data, mime=True)
        except Exception:
            pass
    ext = Path(filename).suffix.lower()
    ext_map = {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
        ".pdf": "application/pdf", ".zip": "application/zip",
        ".exe": "application/octet-stream", ".html": "text/html",
        ".txt": "text/plain", ".doc": "application/msword",
    }
    return ext_map.get(ext, "application/octet-stream")


def _unchunk(body: bytes) -> bytes:
    out = bytearray()
    view = memoryview(body)
    i = 0
    while i < len(view):
        end = bytes(view[i:]).find(b"\r\n")
        if end == -1:
            break
        size_str = bytes(view[i:i + end]).decode("ascii", errors="ignore").split(";")[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            break
        i += end + 2
        out.extend(bytes(view[i:i + size]))
        i += size + 2
    return bytes(out)


def _decompress(data: bytes, encoding: str) -> bytes:
    enc = encoding.lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(data)
        if enc in ("deflate", "zlib"):
            try:
                return zlib.decompress(data)
            except Exception:
                return zlib.decompress(data, -15)
    except Exception:
        pass
    return data


def _parse_content_disposition(header: str) -> str:
    m = re.search(r'filename\*?=["\']?([^"\';\r\n]+)', header, re.IGNORECASE)
    if m:
        name = m.group(1).strip().strip('"').strip("'")
        # Handle RFC 5987 encoding
        if name.startswith("UTF-8''"):
            from urllib.parse import unquote
            name = unquote(name[7:])
        return name
    return ""


class FileExtractor:
    """Extract files from HTTP, FTP-DATA, SMTP streams."""

    def __init__(self, output_dir: str = None):
        self._files = []
        self._output_dir = output_dir or settings.OUTPUT_DIR
        os.makedirs(self._output_dir, exist_ok=True)
        self._ftp_state = {}  # key -> {filename, data_port, mode}

    def process_stream(self, stream_key, payload_bytes: bytes, direction: str) -> None:
        try:
            self._process_http(stream_key, payload_bytes, direction)
        except Exception:
            pass
        try:
            self._process_smtp(stream_key, payload_bytes, direction)
        except Exception:
            pass
        try:
            self._carve_files(stream_key, payload_bytes, direction)
        except Exception:
            pass

    def _process_http(self, stream_key, payload: bytes, direction: str) -> None:
        # Look for HTTP response
        if not payload:
            return
        text_start = payload[:4].decode("latin-1", errors="ignore")
        if not text_start.startswith("HTTP"):
            return

        header_end = payload.find(b"\r\n\r\n")
        if header_end == -1:
            return

        header_block = payload[:header_end].decode("utf-8", errors="ignore")
        body = payload[header_end + 4:]

        headers = {}
        lines = header_block.split("\r\n")
        status_line = lines[0]
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v

        content_type = headers.get("content-type", "")
        content_encoding = headers.get("content-encoding", "")
        content_disposition = headers.get("content-disposition", "")
        transfer_encoding = headers.get("transfer-encoding", "")
        content_length = headers.get("content-length", "")

        # Unchunk
        if "chunked" in transfer_encoding.lower():
            body = _unchunk(body)

        # Decompress
        if content_encoding:
            body = _decompress(body, content_encoding)

        if not body:
            return

        # Determine filename
        filename = ""
        if content_disposition:
            filename = _parse_content_disposition(content_disposition)

        if not filename:
            # Try URL from stream key
            filename = "http_response"
            try:
                url_path = ""
                if isinstance(stream_key, tuple) and len(stream_key) >= 4:
                    pass
                if not filename:
                    filename = "http_response"
            except Exception:
                pass

        filename = _safe_filename(filename)
        if not os.path.splitext(filename)[1]:
            # guess ext from content-type
            ct = content_type.split(";")[0].strip().lower()
            ct_ext = {
                "image/jpeg": ".jpg", "image/png": ".png", "application/pdf": ".pdf",
                "application/zip": ".zip", "text/html": ".html", "text/plain": ".txt",
            }
            filename += ct_ext.get(ct, ".bin")

        self._save_file(filename, body, stream_key, "HTTP", content_type)

    def _process_smtp(self, stream_key, payload: bytes, direction: str) -> None:
        text = payload.decode("latin-1", errors="ignore")
        if "\r\nDATA\r\n" not in text and "Content-Type: multipart" not in text:
            return
        # Find email body after DATA command
        data_start = text.find("\r\nDATA\r\n")
        if data_start != -1:
            email_bytes = payload[data_start + 8:]
        else:
            email_bytes = payload

        try:
            parser = email.parser.BytesParser()
            msg = parser.parsebytes(email_bytes)
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                cd = part.get("Content-Disposition", "")
                if "attachment" in cd.lower():
                    filename = part.get_filename() or "smtp_attachment"
                    filename = _safe_filename(filename)
                    body = part.get_payload(decode=True)
                    if body:
                        self._save_file(filename, body, stream_key, "SMTP", part.get_content_type())
        except Exception:
            pass

    def _carve_files(self, stream_key, payload: bytes, direction: str) -> None:
        for sig, file_type, ext in FILE_SIGNATURES:
            offset = 0
            while True:
                idx = payload.find(sig, offset)
                if idx == -1:
                    break
                carved = payload[idx:idx + 10 * 1024 * 1024]  # up to 10MB
                if len(carved) > 64:
                    filename = f"carved_{file_type}{ext}"
                    self._save_file(filename, carved, stream_key, "CARVED", "")
                offset = idx + len(sig)
                break  # one per sig per stream

    def _save_file(self, filename: str, data: bytes, stream_key, protocol: str, mime_type: str) -> None:
        if not data or len(data) < 16:
            return
        out_path = _unique_path(self._output_dir, filename)
        try:
            with open(out_path, "wb") as f:
                f.write(data)
        except Exception:
            return

        hashes = _hash_bytes(data)
        detected_mime = _detect_mime(data, filename) if not mime_type else mime_type

        src_ip = dst_ip = ""
        if isinstance(stream_key, tuple) and len(stream_key) >= 4:
            src_ip = str(stream_key[0])
            dst_ip = str(stream_key[2])

        self._files.append({
            "filename": filename,
            "path": out_path,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "mime_type": detected_mime,
            "size": len(data),
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "vt_status": "pending",
            "timestamp": None,
        })

    @property
    def files(self):
        return self._files
