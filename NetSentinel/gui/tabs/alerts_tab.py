"""Alerts tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                              QTableWidgetItem, QHeaderView, QAbstractItemView,
                              QComboBox, QLabel, QPushButton, QSplitter)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor

from gui.widgets.filter_bar import FilterBar
from gui.widgets.detail_panel import DetailPanel

COLUMNS = ["Timestamp", "Severity", "Rule", "Description", "Src IP", "Dst IP"]

SEV_COLORS = {
    "CRITICAL": QColor("#5a1a1a"),
    "HIGH": QColor("#4a2a1a"),
    "MEDIUM": QColor("#4a3a1a"),
    "LOW": QColor("#1a2a4a"),
    "INFO": QColor("#2a2a2a"),
}

SEV_TEXT_COLORS = {
    "CRITICAL": QColor("#ff6b6b"),
    "HIGH": QColor("#e17055"),
    "MEDIUM": QColor("#fdcb6e"),
    "LOW": QColor("#74b9ff"),
    "INFO": QColor("#b2bec3"),
}


class AlertsTab(QWidget):
    alert_selected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        top = QHBoxLayout()
        self._filter = FilterBar("Filter alerts...")
        self._filter.filter_changed.connect(self._apply_filter)
        top.addWidget(self._filter)

        top.addWidget(QLabel("Severity:"))
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self._sev_filter.currentTextChanged.connect(self._apply_filter)
        top.addWidget(self._sev_filter)

        self._count_lbl = QLabel("0 alerts")
        self._count_lbl.setStyleSheet("color: #e94560; font-weight: bold; padding: 4px 8px;")
        top.addWidget(self._count_lbl)

        layout.addLayout(top)

        splitter = QSplitter(Qt.Vertical)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.itemSelectionChanged.connect(self._on_selection)
        splitter.addWidget(self._table)

        self._detail = DetailPanel()
        splitter.addWidget(self._detail)
        splitter.setSizes([400, 150])

        layout.addWidget(splitter)

    def update_alerts(self, alerts_list: list) -> None:
        self._alerts = alerts_list
        self._populate(alerts_list)

    def _populate(self, alerts: list) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        filter_text = self._filter.get_text().lower()
        sev_filter = self._sev_filter.currentText()

        shown = 0
        for a in alerts:
            sev = a.get("severity", "")
            if sev_filter != "All" and sev != sev_filter:
                continue
            if filter_text:
                row_str = f"{a.get('rule_name','')} {a.get('description','')} {' '.join(a.get('related_ips',[]))}".lower()
                if filter_text not in row_str:
                    continue

            row = self._table.rowCount()
            self._table.insertRow(row)
            shown += 1

            ips = a.get("related_ips", [])
            src_ip = ips[0] if len(ips) > 0 else ""
            dst_ip = ips[1] if len(ips) > 1 else ""

            values = [
                a.get("timestamp_str", ""),
                sev,
                a.get("rule_name", ""),
                a.get("description", ""),
                src_ip,
                dst_ip,
            ]

            bg = SEV_COLORS.get(sev)
            fg = SEV_TEXT_COLORS.get(sev)

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, a)
                if bg:
                    item.setBackground(bg)
                if fg and col == 1:
                    item.setForeground(fg)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)
        self._count_lbl.setText(f"{shown} alerts")

    def _apply_filter(self, _=None) -> None:
        self._populate(self._alerts)

    def _on_selection(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            return
        alert = rows[0].data(Qt.UserRole)
        if alert:
            self._detail.show_alert(alert)
            self.alert_selected.emit(alert)
