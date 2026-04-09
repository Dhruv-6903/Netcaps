"""Filter bar widget."""
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QPushButton, QLabel
from PyQt5.QtCore import pyqtSignal, Qt


class FilterBar(QWidget):
    """Filter bar with real-time filtering signal."""

    filter_changed = pyqtSignal(str)

    def __init__(self, placeholder: str = "Filter...", parent=None):
        super().__init__(parent)
        self._build_ui(placeholder)

    def _build_ui(self, placeholder: str) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(4)

        self._label = QLabel("🔍")
        layout.addWidget(self._label)

        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        self._input.textChanged.connect(self._on_text_changed)
        layout.addWidget(self._input)

        self._clear_btn = QPushButton("✕")
        self._clear_btn.setFixedWidth(28)
        self._clear_btn.clicked.connect(self.clear)
        layout.addWidget(self._clear_btn)

    def _on_text_changed(self, text: str) -> None:
        self.filter_changed.emit(text)

    def clear(self) -> None:
        self._input.clear()

    def get_text(self) -> str:
        return self._input.text()
