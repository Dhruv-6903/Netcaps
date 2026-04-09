"""Hosts tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                              QTableWidgetItem, QHeaderView, QSplitter,
                              QAbstractItemView, QMenu, QAction)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
import subprocess
import sys

from gui.widgets.filter_bar import FilterBar
from gui.widgets.detail_panel import DetailPanel


COLUMNS = ["IP", "MAC", "Hostname", "OS", "Vendor", "Country", "ASN",
           "First Seen", "Last Seen", "Bytes In", "Bytes Out", "Ports", "Router"]


def _ts(ts):
    if ts is None:
        return ""
    try:
        from datetime import datetime
        return datetime.utcfromtimestamp(float(ts)).strftime("%H:%M:%S")
    except Exception:
        return str(ts)


class HostsTab(QWidget):
    ip_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hosts = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter = FilterBar("Filter hosts...")
        self._filter.filter_changed.connect(self._apply_filter)
        layout.addWidget(self._filter)

        splitter = QSplitter(Qt.Vertical)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.itemSelectionChanged.connect(self._on_selection)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)

        self._detail = DetailPanel()

        splitter.addWidget(self._table)
        splitter.addWidget(self._detail)
        splitter.setSizes([400, 200])
        layout.addWidget(splitter)

    def update_hosts(self, hosts_dict: dict) -> None:
        self._hosts = hosts_dict
        self._populate(hosts_dict)

    def _populate(self, hosts: dict) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        filter_text = self._filter.get_text().lower()

        for ip, h in hosts.items():
            if filter_text and filter_text not in ip.lower():
                hostnames = ",".join(h.get("hostnames", set()))
                if filter_text not in hostnames.lower():
                    continue

            row = self._table.rowCount()
            self._table.insertRow(row)

            hostnames_str = ",".join(sorted(h.get("hostnames", set())))
            ports_str = ",".join(str(p) for p in sorted(h.get("dst_ports", set()))[:10])

            values = [
                ip,
                h.get("mac", ""),
                hostnames_str,
                h.get("os_guess", ""),
                h.get("vendor", ""),
                h.get("country", ""),
                h.get("asn", ""),
                _ts(h.get("first_seen")),
                _ts(h.get("last_seen")),
                str(h.get("bytes_recv", 0)),
                str(h.get("bytes_sent", 0)),
                ports_str,
                "✓" if h.get("is_router") else "",
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, ip)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

    def _apply_filter(self, text: str) -> None:
        self._populate(self._hosts)

    def _on_selection(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            return
        ip = rows[0].data(Qt.UserRole)
        if ip and ip in self._hosts:
            self._detail.show_host(self._hosts[ip])
            self.ip_selected.emit(ip)

    def _context_menu(self, pos) -> None:
        item = self._table.itemAt(pos)
        if not item:
            return
        ip = item.data(Qt.UserRole)
        menu = QMenu(self)

        copy_ip = QAction("Copy IP", self)
        copy_ip.triggered.connect(lambda: self._copy_text(ip))
        menu.addAction(copy_ip)

        row = item.row()
        row_data = [self._table.item(row, c).text() for c in range(self._table.columnCount())]
        copy_csv = QAction("Copy Row as CSV", self)
        copy_csv.triggered.connect(lambda: self._copy_text(",".join(row_data)))
        menu.addAction(copy_csv)

        vt = QAction("Lookup on VirusTotal", self)
        vt.triggered.connect(lambda: self._open_url(f"https://www.virustotal.com/gui/ip-address/{ip}"))
        menu.addAction(vt)

        shodan = QAction("Lookup on Shodan", self)
        shodan.triggered.connect(lambda: self._open_url(f"https://www.shodan.io/host/{ip}"))
        menu.addAction(shodan)

        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy_text(self, text: str) -> None:
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)

    def _open_url(self, url: str) -> None:
        import webbrowser
        webbrowser.open(url)
