"""Credentials tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                              QTableWidgetItem, QHeaderView, QAbstractItemView,
                              QPushButton, QMenu, QAction, QLabel)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from gui.widgets.filter_bar import FilterBar

COLUMNS = ["Protocol", "Username", "Password", "Src IP", "Dst IP", "Timestamp"]
ROW_COLOR = QColor("#3d1a1a")


def _ts(ts):
    if ts is None:
        return ""
    try:
        from datetime import datetime
        return datetime.utcfromtimestamp(float(ts)).strftime("%H:%M:%S")
    except Exception:
        return str(ts)


class CredentialsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._credentials = []
        self._masked = True
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        top = QHBoxLayout()
        self._filter = FilterBar("Filter credentials...")
        self._filter.filter_changed.connect(self._apply_filter)
        top.addWidget(self._filter)

        self._mask_btn = QPushButton("Show Passwords")
        self._mask_btn.setCheckable(True)
        self._mask_btn.toggled.connect(self._toggle_mask)
        top.addWidget(self._mask_btn)

        warning = QLabel("⚠ Sensitive Data")
        warning.setStyleSheet("color: #e94560; font-weight: bold;")
        top.addWidget(warning)

        layout.addLayout(top)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self._table)

    def update_credentials(self, creds_list: list) -> None:
        self._credentials = creds_list
        self._populate(creds_list)

    def _populate(self, creds: list) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        filter_text = self._filter.get_text().lower()

        for c in creds:
            if filter_text:
                row_str = f"{c.get('protocol','')} {c.get('username','')} {c.get('src_ip','')}".lower()
                if filter_text not in row_str:
                    continue
            row = self._table.rowCount()
            self._table.insertRow(row)

            passwd = c.get("password", "") if not self._masked else "●●●●●●●●"

            values = [
                c.get("protocol", ""),
                c.get("username", ""),
                passwd,
                c.get("src_ip", ""),
                c.get("dst_ip", ""),
                _ts(c.get("timestamp")),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setBackground(ROW_COLOR)
                item.setData(Qt.UserRole, c)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

    def _toggle_mask(self, checked: bool) -> None:
        self._masked = not checked
        self._mask_btn.setText("Hide Passwords" if checked else "Show Passwords")
        self._populate(self._credentials)

    def _apply_filter(self, text: str) -> None:
        self._populate(self._credentials)

    def _context_menu(self, pos) -> None:
        item = self._table.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        copy = QAction("Copy to Clipboard", self)
        copy.triggered.connect(lambda: self._copy(item.text()))
        menu.addAction(copy)
        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy(self, text: str) -> None:
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
