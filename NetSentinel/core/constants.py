"""Shared constants for NetSentinel core modules."""

# Maximum size for TCP stream payload buffers (10 MB)
MAX_STREAM_SIZE = 10 * 1024 * 1024

# Threshold for data exfiltration alert (100 MB)
EXFIL_THRESHOLD = 100 * 1024 * 1024

# Magic byte signatures for file type detection
# Format: {bytes_prefix: (description, extension)}
MAGIC_SIGNATURES = {
    b"\x25\x50\x44\x46": ("PDF", ".pdf"),
    b"\xff\xd8\xff": ("JPEG", ".jpg"),
    b"\x89\x50\x4e\x47": ("PNG", ".png"),
    b"\x50\x4b\x03\x04": ("ZIP", ".zip"),
    b"\x4d\x5a": ("MZ/EXE", ".exe"),
    b"\xd0\xcf\x11\xe0": ("OLE/Office", ".doc"),
}
