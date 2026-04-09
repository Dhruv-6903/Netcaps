"""Files tab."""
import os
import subprocess
import sys

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
                              QHeaderView, QAbstractItemView, QMenu, QAction, QDialog,
                              QVBoxLayout as QVL)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from gui.widgets.filter_bar import FilterBar
from gui.widgets.hex_viewer import HexViewer

COLUMNS = ["Filename", "Protocol", "Src IP", "Dst IP", "MIME", "Size", "MD5", "VT Status", "Timestamp"]

VT_COLORS = {
    "clean": QColor("#00b894"),
    "malicious": QColor("#d63031"),
    "pending": QColor("#a0a0b0"),
    "not_found": QColor("#636e72"),
    "error": QColor("#a0a0b0"),
}


def _ts(ts):
    if ts is None:
        return ""
    try:
        from datetime import datetime
        return datetime.utcfromtimestamp(float(ts)).strftime("%H:%M:%S")
    except Exception:
        return str(ts)


def _fmt_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.1f} MB"


class FilesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._files = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter = FilterBar("Filter files...")
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

    def update_files(self, files_list: list) -> None:
        self._files = files_list
        self._populate(files_list)

    def _populate(self, files: list) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        filter_text = self._filter.get_text().lower()

        for f in files:
            if filter_text and filter_text not in f.get("filename", "").lower():
                if filter_text not in f.get("mime_type", "").lower():
                    continue

            row = self._table.rowCount()
            self._table.insertRow(row)
            vt = f.get("vt_status", "pending")
            values = [
                f.get("filename", ""),
                f.get("protocol", ""),
                f.get("src_ip", ""),
                f.get("dst_ip", ""),
                f.get("mime_type", ""),
                _fmt_size(f.get("size", 0)),
                f.get("md5", ""),
                vt,
                _ts(f.get("timestamp")),
            ]
            color = VT_COLORS.get(vt)
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, f)
                if col == 7 and color:
                    item.setForeground(color)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)

    def _apply_filter(self, text: str) -> None:
        self._populate(self._files)

    def _on_double_click(self, index) -> None:
        item = self._table.item(index.row(), 0)
        if not item:
            return
        f = item.data(Qt.UserRole)
        if f and f.get("path") and os.path.exists(f["path"]):
            self._open_file(f["path"])

    def _open_file(self, path: str) -> None:
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    def _context_menu(self, pos) -> None:
        item = self._table.itemAt(pos)
        if not item:
            return
        f = item.data(Qt.UserRole) or {}
        menu = QMenu(self)

        open_act = QAction("Open File", self)
        open_act.triggered.connect(lambda: self._open_file(f.get("path", "")))
        menu.addAction(open_act)

        copy_hash = QAction("Copy MD5 Hash", self)
        copy_hash.triggered.connect(lambda: self._copy(f.get("md5", "")))
        menu.addAction(copy_hash)

        hex_act = QAction("Show in Hex Viewer", self)
        hex_act.triggered.connect(lambda: self._show_hex(f.get("path", "")))
        menu.addAction(hex_act)

        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy(self, text: str) -> None:
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)

    def _show_hex(self, path: str) -> None:
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "rb") as fh:
                data = fh.read(1024 * 1024)
        except Exception:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Hex View: {os.path.basename(path)}")
        dlg.resize(900, 600)
        lay = QVL(dlg)
        viewer = HexViewer()
        viewer.load_data(data)
        lay.addWidget(viewer)
        dlg.exec_()
