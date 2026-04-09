"""DNS tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QSplitter, QTableWidget,
                              QTableWidgetItem, QHeaderView, QAbstractItemView,
                              QTextEdit, QLabel)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from gui.widgets.filter_bar import FilterBar

COLUMNS = ["FQDN", "Type", "Response", "Src IP", "Dst IP", "Timestamp", "TTL", "Flags"]

COLOR_NORMAL = None
COLOR_SUSPICIOUS = QColor("#7d6c1a")
COLOR_MALICIOUS = QColor("#5a1a1a")
COLOR_ENCRYPTED = QColor("#2a2a4a")


def _ts(ts):
    if ts is None:
        return ""
    try:
        from datetime import datetime
        return datetime.utcfromtimestamp(float(ts)).strftime("%H:%M:%S")
    except Exception:
        return str(ts)


class DnsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._events = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter = FilterBar("Filter DNS...")
        self._filter.filter_changed.connect(self._apply_filter)
        layout.addWidget(self._filter)

        splitter = QSplitter(Qt.Vertical)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.itemSelectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(150)
        splitter.addWidget(self._detail)

        layout.addWidget(splitter)

    def update_dns(self, events_list: list) -> None:
        self._events = events_list
        self._populate(events_list)

    def _populate(self, events: list) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        filter_text = self._filter.get_text().lower()

        for ev in events:
            fqdn = ev.get("fqdn", "")
            if filter_text and filter_text not in fqdn.lower():
                if filter_text not in ev.get("src_ip", "").lower():
                    continue

            tags = ev.get("tags", [])
            flags_str = ",".join(tags) if tags else "normal"
            responses = ",".join(ev.get("response_ips", []))
            ttl = str(ev.get("ttl", "")) if ev.get("ttl") is not None else ""

            row = self._table.rowCount()
            self._table.insertRow(row)

            values = [
                fqdn,
                ev.get("query_type", ""),
                responses,
                ev.get("src_ip", ""),
                ev.get("dst_ip", ""),
                _ts(ev.get("timestamp")),
                ttl,
                flags_str,
            ]

            if ev.get("is_nxdomain") or any(t in ("c2_dga", "dga", "dns_tunneling") for t in tags):
                row_color = COLOR_MALICIOUS
            elif tags:
                row_color = COLOR_SUSPICIOUS
            elif ev.get("query_type") == "HTTPS":
                row_color = COLOR_ENCRYPTED
            else:
                row_color = None

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, ev)
                if row_color:
                    item.setBackground(row_color)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

    def _apply_filter(self, text: str) -> None:
        self._populate(self._events)

    def _on_selection(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            return
        ev = rows[0].data(Qt.UserRole)
        if ev:
            details = (
                f"<b>FQDN:</b> {ev.get('fqdn', '')}<br>"
                f"<b>Type:</b> {ev.get('query_type', '')}<br>"
                f"<b>Responses:</b> {', '.join(ev.get('response_ips', []))}<br>"
                f"<b>CNAMEs:</b> {', '.join(ev.get('cnames', []))}<br>"
                f"<b>TTL:</b> {ev.get('ttl', 'N/A')}<br>"
                f"<b>Latency:</b> {ev.get('latency_ms', 0):.1f}ms<br>"
                f"<b>Tags:</b> {', '.join(ev.get('tags', []))}<br>"
                f"<b>NXDOMAIN:</b> {ev.get('is_nxdomain', False)}"
            )
            self._detail.setHtml(details)
