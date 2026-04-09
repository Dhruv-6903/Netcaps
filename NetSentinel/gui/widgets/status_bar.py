"""Status bar widget."""
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel, QProgressBar
from PyQt5.QtCore import Qt


class StatusBar(QWidget):
    """Custom status bar showing analysis metrics."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(24)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 0, 6, 0)
        layout.setSpacing(12)

        self._packets_lbl = QLabel("Packets: 0")
        self._hosts_lbl = QLabel("Hosts: 0")
        self._sessions_lbl = QLabel("Sessions: 0")
        self._alerts_lbl = QLabel("Alerts: 0")
        self._source_lbl = QLabel("")
        self._live_lbl = QLabel("● LIVE")
        self._live_lbl.setStyleSheet("color: #00b894; font-weight: bold;")
        self._live_lbl.hide()

        self._progress = QProgressBar()
        self._progress.setFixedWidth(150)
        self._progress.setFixedHeight(12)
        self._progress.hide()

        for lbl in (self._packets_lbl, self._hosts_lbl,
                    self._sessions_lbl, self._alerts_lbl):
            layout.addWidget(lbl)

        layout.addStretch()
        layout.addWidget(self._source_lbl)
        layout.addWidget(self._live_lbl)
        layout.addWidget(self._progress)

    def update_counts(self, packets: int, hosts: int, sessions: int, alerts: int) -> None:
        self._packets_lbl.setText(f"Packets: {packets:,}")
        self._hosts_lbl.setText(f"Hosts: {hosts:,}")
        self._sessions_lbl.setText(f"Sessions: {sessions:,}")
        color = "#e94560" if alerts > 0 else "#eaeaea"
        self._alerts_lbl.setText(f"Alerts: {alerts:,}")
        self._alerts_lbl.setStyleSheet(f"color: {color}; font-weight: bold;" if alerts > 0 else "")

    def set_progress(self, value: int, maximum: int = 100) -> None:
        self._progress.setMaximum(maximum)
        self._progress.setValue(value)
        if value >= maximum or maximum == 0:
            self._progress.hide()
        else:
            self._progress.show()

    def set_source(self, text: str) -> None:
        self._source_lbl.setText(text)

    def set_live(self, live: bool) -> None:
        if live:
            self._live_lbl.show()
        else:
            self._live_lbl.hide()
