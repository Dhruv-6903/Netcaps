"""Threat badge widget."""
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel
from PyQt5.QtCore import Qt

STATUS_COLORS = {
    "Clean": "#00b894",
    "Suspicious": "#fdcb6e",
    "Malicious": "#d63031",
    "Unknown": "#636e72",
    "pending": "#a0a0b0",
    "clean": "#00b894",
    "malicious": "#d63031",
    "not_found": "#636e72",
    "error": "#a0a0b0",
}


class ThreatBadge(QWidget):
    """Visual threat status badge."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._lbl = QLabel("Unknown")
        self._lbl.setAlignment(Qt.AlignCenter)
        self._lbl.setMinimumWidth(80)
        self._set_color("Unknown")
        layout.addWidget(self._lbl)

    def _set_color(self, status: str) -> None:
        color = STATUS_COLORS.get(status, "#636e72")
        self._lbl.setStyleSheet(
            f"background-color: {color}; color: #fff; border-radius: 4px; "
            f"padding: 2px 6px; font-size: 11px; font-weight: bold;"
        )

    def set_status(self, status: str, detail: str = "") -> None:
        display = status.capitalize() if status else "Unknown"
        self._lbl.setText(display)
        self._set_color(status)
        if detail:
            self._lbl.setToolTip(detail)
