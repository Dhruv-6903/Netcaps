"""Chat tab for AIM/OSCAR conversations."""
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QListWidget,
                              QListWidgetItem, QTextEdit, QSplitter, QLabel)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from gui.widgets.filter_bar import FilterBar


class ChatTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._conversations = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter = FilterBar("Search messages...")
        layout.addWidget(self._filter)

        splitter = QSplitter(Qt.Horizontal)

        # Left: conversation list
        left = QWidget()
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.addWidget(QLabel("Conversations"))
        self._conv_list = QListWidget()
        self._conv_list.itemSelectionChanged.connect(self._on_conv_selected)
        left_lay.addWidget(self._conv_list)
        splitter.addWidget(left)

        # Right: chat thread
        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.addWidget(QLabel("Messages"))
        self._thread_view = QTextEdit()
        self._thread_view.setReadOnly(True)
        self._thread_view.setFont(QFont("Segoe UI", 11))
        right_lay.addWidget(self._thread_view)
        splitter.addWidget(right)

        splitter.setSizes([250, 550])
        layout.addWidget(splitter)

    def update_chats(self, conversations_dict: dict) -> None:
        self._conversations = conversations_dict
        self._conv_list.clear()
        for key in conversations_dict:
            participants = " ↔ ".join(sorted(str(p) for p in key))
            item = QListWidgetItem(participants)
            item.setData(Qt.UserRole, key)
            self._conv_list.addItem(item)

    def _on_conv_selected(self) -> None:
        items = self._conv_list.selectedItems()
        if not items:
            return
        key = items[0].data(Qt.UserRole)
        messages = self._conversations.get(key, [])
        self._render_thread(messages)

    def _render_thread(self, messages: list) -> None:
        html_parts = []
        for msg in sorted(messages, key=lambda m: (m.get("timestamp") or 0)):
            sender = msg.get("sender", "")
            text = msg.get("text", "")
            ts = msg.get("timestamp")
            ts_str = ""
            if ts:
                try:
                    from datetime import datetime
                    ts_str = datetime.utcfromtimestamp(float(ts)).strftime("%H:%M:%S")
                except Exception:
                    ts_str = str(ts)

            color = "#74b9ff" if msg.get("direction") == "fwd" else "#fd79a8"
            html_parts.append(
                f'<div style="margin:4px 0">'
                f'<span style="color:{color};font-weight:bold">{sender}</span> '
                f'<span style="color:#a0a0b0;font-size:0.85em">[{ts_str}]</span><br>'
                f'<span style="color:#eaeaea">{text}</span>'
                f'</div>'
            )
        self._thread_view.setHtml("".join(html_parts) if html_parts else "<i>No messages</i>")
