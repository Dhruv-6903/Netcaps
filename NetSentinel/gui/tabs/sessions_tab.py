"""Sessions tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
                              QHeaderView, QAbstractItemView, QMenu, QAction)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from gui.widgets.filter_bar import FilterBar
from gui.widgets.stream_viewer import StreamViewer


COLUMNS = ["#", "Protocol", "App", "Src IP", "Src Port", "Dst IP", "Dst Port",
           "Start", "Duration", "Bytes Fwd", "Bytes Bwd", "State", "JA3", "TLS Ver"]

PROTO_COLORS = {
    "HTTP": QColor("#74b9ff"),
    "DNS": QColor("#00b894"),
    "HTTPS": QColor("#636e72"),
    "TLS": QColor("#636e72"),
    "SSH": QColor("#fdcb6e"),
}


def _ts(ts):
    if ts is None:
        return ""
    try:
        from datetime import datetime
        return datetime.utcfromtimestamp(float(ts)).strftime("%H:%M:%S")
    except Exception:
        return str(ts)


class SessionsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._sessions = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter = FilterBar("Filter sessions...")
        self._filter.filter_changed.connect(self._apply_filter)
        layout.addWidget(self._filter)

        self._table = QTableWidget(0, len(COLUMNS))
        self._table.setHorizontalHeaderLabels(COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self._table)

    def update_sessions(self, sessions_list: list) -> None:
        self._sessions = sessions_list
        self._populate(sessions_list)

    def _populate(self, sessions: list) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        filter_text = self._filter.get_text().lower()

        for i, s in enumerate(sessions):
            if filter_text:
                row_text = f"{s.get('src_ip','')} {s.get('dst_ip','')} {s.get('app_label','')} {s.get('protocol','')}".lower()
                if filter_text not in row_text:
                    continue

            row = self._table.rowCount()
            self._table.insertRow(row)

            app = s.get("app_label", s.get("protocol", ""))
            state = s.get("state", "")
            flags = s.get("tcp_flags", set())
            is_suspicious = state == "CLOSED" and not ({"SYN", "ACK"} <= set(flags))

            values = [
                str(i + 1),
                s.get("protocol", ""),
                app,
                s.get("src_ip", ""),
                str(s.get("src_port", "")),
                s.get("dst_ip", ""),
                str(s.get("dst_port", "")),
                _ts(s.get("start_time")),
                f"{s.get('duration', 0):.1f}s",
                str(s.get("bytes_src_to_dst", 0)),
                str(s.get("bytes_dst_to_src", 0)),
                state,
                s.get("ja3_hash", "")[:16] if s.get("ja3_hash") else "",
                s.get("tls_version", ""),
            ]

            color = PROTO_COLORS.get(app, None)
            if is_suspicious:
                color = QColor("#e94560")

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, i)
                if color:
                    item.setForeground(color)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

    def _apply_filter(self, text: str) -> None:
        self._populate(self._sessions)

    def _on_double_click(self, index) -> None:
        item = self._table.item(index.row(), 0)
        if item is None:
            return
        sess_idx = item.data(Qt.UserRole)
        if sess_idx is None or sess_idx >= len(self._sessions):
            return
        sess = self._sessions[sess_idx]
        viewer = StreamViewer(self)
        viewer.load_stream(sess.get("payload_fwd", b""), sess.get("payload_bwd", b""))
        viewer.exec_()

    def _context_menu(self, pos) -> None:
        item = self._table.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        copy = QAction("Copy Row", self)
        row = item.row()
        row_data = [self._table.item(row, c).text() for c in range(self._table.columnCount())]
        copy.triggered.connect(lambda: self._copy(",".join(row_data)))
        menu.addAction(copy)
        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy(self, text: str) -> None:
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
