"""Timeline tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QListWidget,
                              QListWidgetItem, QTextEdit, QLabel, QComboBox,
                              QSplitter)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from gui.widgets.filter_bar import FilterBar

CATEGORY_ICONS = {
    "credential": "🔑",
    "file": "📁",
    "dns": "🌐",
    "alert": "⚠",
    "session": "🔗",
    "email": "✉",
    "chat": "💬",
    "tls": "🔒",
    "other": "•",
}

SEV_COLORS = {
    "CRITICAL": "#ff6b6b",
    "HIGH": "#e17055",
    "MEDIUM": "#fdcb6e",
    "LOW": "#74b9ff",
    "INFO": "#b2bec3",
}


class TimelineTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._events = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        filters = QHBoxLayout()
        self._filter = FilterBar("Filter timeline...")
        self._filter.filter_changed.connect(self._apply_filter)
        filters.addWidget(self._filter)

        filters.addWidget(QLabel("Category:"))
        self._cat_filter = QComboBox()
        self._cat_filter.addItems(["All", "credential", "file", "dns", "alert",
                                    "session", "email", "chat", "tls"])
        self._cat_filter.currentTextChanged.connect(self._apply_filter)
        filters.addWidget(self._cat_filter)

        filters.addWidget(QLabel("Severity:"))
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self._sev_filter.currentTextChanged.connect(self._apply_filter)
        filters.addWidget(self._sev_filter)

        layout.addLayout(filters)

        splitter = QSplitter(Qt.Vertical)

        self._list = QListWidget()
        self._list.setFont(QFont("Consolas", 10))
        splitter.addWidget(self._list)

        narrative_panel = QWidget()
        nar_lay = QVBoxLayout(narrative_panel)
        nar_lay.setContentsMargins(0, 0, 0, 0)
        nar_lay.addWidget(QLabel("Attack Narrative:"))
        self._narrative = QTextEdit()
        self._narrative.setReadOnly(True)
        self._narrative.setMaximumHeight(180)
        nar_lay.addWidget(self._narrative)
        splitter.addWidget(narrative_panel)

        splitter.setSizes([500, 180])
        layout.addWidget(splitter)

    def update_timeline(self, events_list: list) -> None:
        self._events = events_list
        self._populate(events_list)

    def set_narrative(self, text: str) -> None:
        self._narrative.setPlainText(text)

    def _populate(self, events: list) -> None:
        self._list.clear()
        filter_text = self._filter.get_text().lower()
        cat_filter = self._cat_filter.currentText()
        sev_filter = self._sev_filter.currentText()

        for ev in events:
            if cat_filter != "All" and ev.get("category") != cat_filter:
                continue
            if sev_filter != "All" and ev.get("severity") != sev_filter:
                continue
            desc = ev.get("description", "")
            if filter_text and filter_text not in desc.lower():
                if filter_text not in ev.get("src_ip", "").lower():
                    continue

            icon = CATEGORY_ICONS.get(ev.get("category", ""), "•")
            sev = ev.get("severity", "")
            color = SEV_COLORS.get(sev, "#eaeaea")
            ts_str = ev.get("timestamp_str", "")
            src = ev.get("src_ip", "")
            dst = ev.get("dst_ip", "")

            text = f"{icon} [{ts_str}] {sev:<8} {src}→{dst}  {desc}"
            item = QListWidgetItem(text)
            item.setForeground(QColor(color))
            self._list.addItem(item)

    def _apply_filter(self, _=None) -> None:
        self._populate(self._events)
