"""Stream viewer dialog."""
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QTabWidget, QWidget,
                              QTextEdit, QPushButton, QHBoxLayout, QLabel)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QTextCursor


def _hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


class StreamViewer(QDialog):
    """TCP stream viewer with hex, ASCII, and follow-stream views."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Stream Viewer")
        self.resize(900, 600)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        self._tabs = QTabWidget()
        mono = QFont("Consolas", 10)

        self._hex_view = QTextEdit()
        self._hex_view.setReadOnly(True)
        self._hex_view.setFont(mono)
        self._tabs.addTab(self._hex_view, "Hex Dump")

        self._ascii_view = QTextEdit()
        self._ascii_view.setReadOnly(True)
        self._ascii_view.setFont(mono)
        self._tabs.addTab(self._ascii_view, "Raw ASCII")

        self._follow_view = QTextEdit()
        self._follow_view.setReadOnly(True)
        self._follow_view.setFont(mono)
        self._tabs.addTab(self._follow_view, "Follow Stream")

        layout.addWidget(self._tabs)

        btn_layout = QHBoxLayout()
        self._info_lbl = QLabel("")
        btn_layout.addWidget(self._info_lbl)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def load_stream(self, payload_fwd: bytes, payload_bwd: bytes) -> None:
        fwd = bytes(payload_fwd) if isinstance(payload_fwd, bytearray) else payload_fwd or b""
        bwd = bytes(payload_bwd) if isinstance(payload_bwd, bytearray) else payload_bwd or b""

        self._info_lbl.setText(f"Fwd: {len(fwd):,} bytes | Bwd: {len(bwd):,} bytes")

        # Hex dump
        combined = fwd[:32768] + bwd[:32768]
        self._hex_view.setPlainText(_hex_dump(combined))

        # ASCII
        ascii_text = "".join(chr(b) if 32 <= b < 127 or b in (10, 13, 9) else "." for b in combined[:65536])
        self._ascii_view.setPlainText(ascii_text)

        # Follow stream with directional colors
        cursor = self._follow_view.textCursor()
        self._follow_view.clear()

        fwd_fmt = QTextCharFormat()
        fwd_fmt.setForeground(QColor("#74b9ff"))

        bwd_fmt = QTextCharFormat()
        bwd_fmt.setForeground(QColor("#fd79a8"))

        cursor = self._follow_view.textCursor()

        if fwd:
            cursor.setCharFormat(fwd_fmt)
            fwd_text = "".join(chr(b) if 32 <= b < 127 or b in (10, 13, 9) else "." for b in fwd[:32768])
            cursor.insertText("→ [CLIENT]\n" + fwd_text + "\n")

        if bwd:
            cursor.setCharFormat(bwd_fmt)
            bwd_text = "".join(chr(b) if 32 <= b < 127 or b in (10, 13, 9) else "." for b in bwd[:32768])
            cursor.insertText("\n← [SERVER]\n" + bwd_text + "\n")
