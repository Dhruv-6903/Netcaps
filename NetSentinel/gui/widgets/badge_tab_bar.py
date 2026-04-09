"""Badge tab bar showing counts per tab."""
from PyQt5.QtWidgets import QTabBar
from PyQt5.QtCore import Qt, QRect, QSize
from PyQt5.QtGui import QPainter, QColor, QFont


class BadgeTabBar(QTabBar):
    """Tab bar with count badges."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._badges = {}  # tab_index -> count

    def set_badge_count(self, tab_index: int, count: int) -> None:
        self._badges[tab_index] = count
        self.update()

    def tabSizeHint(self, index: int) -> QSize:
        size = super().tabSizeHint(index)
        badge = self._badges.get(index, 0)
        if badge > 0:
            size.setWidth(size.width() + 28)
        return size

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        for index, count in self._badges.items():
            if count <= 0 or index >= self.count():
                continue
            rect = self.tabRect(index)
            bx = rect.right() - 22
            by = rect.top() + 4
            bw = 20
            bh = 16

            # Use red for alerts tab (index assumed from context), else blue
            is_alert = self.tabText(index).lower().startswith("alert")
            bg = QColor("#e94560") if is_alert else QColor("#0f3460")
            painter.setBrush(bg)
            painter.setPen(Qt.NoPen)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.drawRoundedRect(QRect(bx, by, bw, bh), 8, 8)

            painter.setPen(QColor("#eaeaea"))
            font = QFont()
            font.setPointSize(8)
            font.setBold(True)
            painter.setFont(font)
            label = str(count) if count < 999 else "99+"
            painter.drawText(QRect(bx, by, bw, bh), Qt.AlignCenter, label)
        painter.end()
