"""Emails tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QSplitter, QTableWidget,
                              QTableWidgetItem, QHeaderView, QAbstractItemView,
                              QTextEdit)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from gui.widgets.filter_bar import FilterBar

COLUMNS = ["From", "To", "Subject", "Date", "Has Attachments", "Keywords", "Src IP"]


class EmailsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._emails = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter = FilterBar("Filter emails...")
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

        self._viewer = QTextEdit()
        self._viewer.setReadOnly(True)
        splitter.addWidget(self._viewer)
        splitter.setSizes([300, 200])

        layout.addWidget(splitter)

    def update_emails(self, emails_list: list) -> None:
        self._emails = emails_list
        self._populate(emails_list)

    def _populate(self, emails: list) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        filter_text = self._filter.get_text().lower()

        for email in emails:
            subject = email.get("subject", "")
            from_addr = email.get("from_addr", "")
            if filter_text:
                row_str = f"{from_addr} {subject} {' '.join(email.get('to_list', []))}".lower()
                if filter_text not in row_str:
                    continue

            row = self._table.rowCount()
            self._table.insertRow(row)

            has_att = "✓" if email.get("attachments") else ""
            keywords = ",".join(email.get("keywords_found", []))
            to_str = ",".join(email.get("to_list", []))[:60]

            values = [
                from_addr,
                to_str,
                subject,
                email.get("date", ""),
                has_att,
                keywords,
                email.get("src_ip", ""),
            ]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, email)
                if keywords and col == 5:
                    item.setForeground(QColor("#fdcb6e"))
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

    def _apply_filter(self, text: str) -> None:
        self._populate(self._emails)

    def _on_selection(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            return
        email = rows[0].data(Qt.UserRole)
        if email:
            body = email.get("body_html") or email.get("body_text", "")
            subject = email.get("subject", "")
            from_addr = email.get("from_addr", "")
            to = ", ".join(email.get("to_list", []))
            keywords = ", ".join(email.get("keywords_found", []))
            urls = ", ".join(email.get("embedded_urls", [])[:10])

            html = (f"<b>From:</b> {from_addr}<br>"
                    f"<b>To:</b> {to}<br>"
                    f"<b>Subject:</b> {subject}<br>"
                    f"<b>Keywords:</b> <span style='color:#fdcb6e'>{keywords}</span><br>"
                    f"<b>URLs:</b> {urls}<br><hr>"
                    f"{body}")
            self._viewer.setHtml(html)
