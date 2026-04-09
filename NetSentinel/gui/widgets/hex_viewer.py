"""Hex viewer widget."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
                              QLineEdit, QPushButton, QLabel, QCheckBox)
from PyQt5.QtGui import QFont, QTextCharFormat, QColor, QTextCursor
from PyQt5.QtCore import Qt


MAGIC_SIGNATURES = {
    b"\x25\x50\x44\x46": "PDF",
    b"\xff\xd8\xff": "JPEG",
    b"\x89\x50\x4e\x47": "PNG",
    b"\x50\x4b\x03\x04": "ZIP",
    b"\x4d\x5a": "MZ/EXE",
    b"\xd0\xcf\x11\xe0": "OLE/Office",
}


def _hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, min(len(data), 65536), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    if len(data) > 65536:
        lines.append(f"... ({len(data) - 65536:,} more bytes)")
    return "\n".join(lines)


class HexViewer(QWidget):
    """Hex viewer with search capability."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = b""
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Search bar
        search_bar = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search (hex or ASCII)...")
        search_bar.addWidget(self._search_input)

        self._hex_mode_cb = QCheckBox("Hex")
        search_bar.addWidget(self._hex_mode_cb)

        search_btn = QPushButton("Find")
        search_btn.clicked.connect(self._do_search)
        search_bar.addWidget(search_btn)

        self._magic_lbl = QLabel("")
        self._magic_lbl.setStyleSheet("color: #00b894; font-weight: bold;")
        search_bar.addWidget(self._magic_lbl)

        layout.addLayout(search_bar)

        # Hex view
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Consolas", 10))
        layout.addWidget(self._text)

    def load_data(self, data: bytes) -> None:
        self._data = data
        self._text.setPlainText(_hex_dump(data))

        # Detect magic bytes
        magic_name = ""
        for sig, name in MAGIC_SIGNATURES.items():
            if data[:len(sig)] == sig:
                magic_name = name
                break
        if magic_name:
            self._magic_lbl.setText(f"Magic: {magic_name}")
        else:
            self._magic_lbl.setText("")

    def search(self, pattern: str, is_hex: bool) -> None:
        if not pattern or not self._data:
            return
        try:
            if is_hex:
                needle = bytes.fromhex(pattern.replace(" ", ""))
            else:
                needle = pattern.encode("utf-8", errors="ignore")
        except Exception:
            return

        idx = self._data.find(needle)
        if idx == -1:
            self._magic_lbl.setText("Not found")
            return

        # Highlight the line containing idx
        line_num = idx // 16
        doc = self._text.document()
        block = doc.findBlockByLineNumber(line_num)
        cursor = QTextCursor(block)
        cursor.select(QTextCursor.LineUnderCursor)

        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#e94560"))
        cursor.setCharFormat(fmt)
        self._text.setTextCursor(cursor)
        self._text.ensureCursorVisible()
        self._magic_lbl.setText(f"Found at offset 0x{idx:x}")

    def _do_search(self) -> None:
        self.search(self._search_input.text(), self._hex_mode_cb.isChecked())
