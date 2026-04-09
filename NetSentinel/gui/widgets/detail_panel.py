"""Detail panel widget for showing selected item details."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QTextEdit,
                              QGroupBox, QScrollArea)
from PyQt5.QtCore import Qt
from datetime import datetime


def _ts(ts):
    if ts is None:
        return ""
    try:
        return datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _format_dict(d: dict) -> str:
    lines = []
    for k, v in d.items():
        if isinstance(v, (set, frozenset)):
            v = ", ".join(sorted(str(x) for x in v))
        elif isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v[:20])
        elif isinstance(v, bytes):
            v = v.hex()[:64] + "..." if len(v) > 32 else v.hex()
        elif isinstance(v, bytearray):
            v = bytes(v).hex()[:64]
        lines.append(f"<b>{k}:</b> {v}")
    return "<br>".join(lines)


class DetailPanel(QWidget):
    """Resizable detail panel for showing selected row details."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        self._title_lbl = QLabel("Details")
        self._title_lbl.setStyleSheet("font-weight: bold; font-size: 14px; color: #e94560;")
        layout.addWidget(self._title_lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        self._content = QLabel()
        self._content.setWordWrap(True)
        self._content.setTextFormat(Qt.RichText)
        self._content.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self._content.setMargin(8)
        scroll.setWidget(self._content)
        layout.addWidget(scroll)

    def _show_dict(self, title: str, d: dict) -> None:
        self._title_lbl.setText(title)
        self._content.setText(_format_dict(d))

    def show_host(self, host_dict: dict) -> None:
        self._show_dict(f"Host: {host_dict.get('ip', '')}", host_dict)

    def show_session(self, session_dict: dict) -> None:
        display = {k: v for k, v in session_dict.items()
                   if k not in ("payload_fwd", "payload_bwd", "tcp_flags")}
        display["tcp_flags"] = ", ".join(session_dict.get("tcp_flags", set()))
        self._show_dict(f"Session: {session_dict.get('session_id', '')}", display)

    def show_file(self, file_dict: dict) -> None:
        self._show_dict(f"File: {file_dict.get('filename', '')}", file_dict)

    def show_alert(self, alert_dict: dict) -> None:
        self._show_dict(f"Alert: {alert_dict.get('rule_name', '')}", alert_dict)

    def clear(self) -> None:
        self._title_lbl.setText("Details")
        self._content.setText("")
