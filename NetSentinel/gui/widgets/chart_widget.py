"""Chart widget wrapping pyqtgraph."""
import pyqtgraph as pg
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtGui import QColor
import numpy as np


class ChartWidget(QWidget):
    """Wrapper around pyqtgraph PlotWidget for line and bar charts."""

    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self._build_ui(title)

    def _build_ui(self, title: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        pg.setConfigOption("background", "#16213e")
        pg.setConfigOption("foreground", "#eaeaea")

        self._plot = pg.PlotWidget(title=title)
        self._plot.showGrid(x=True, y=True, alpha=0.3)
        self._bar_item = None
        layout.addWidget(self._plot)

    def update_line_chart(self, x_data, y_data, pen_color: str = "#e94560") -> None:
        self._plot.clear()
        pen = pg.mkPen(color=pen_color, width=2)
        self._plot.plot(list(x_data), list(y_data), pen=pen)

    def update_bar_chart(self, categories: list, values: list, color: str = "#0f3460") -> None:
        self._plot.clear()
        if not categories or not values:
            return
        x = list(range(len(categories)))
        bar = pg.BarGraphItem(x=x, height=values, width=0.6,
                              brush=pg.mkBrush(color))
        self._plot.addItem(bar)
        ax = self._plot.getAxis("bottom")
        ax.setTicks([list(zip(x, categories))])

    def clear(self) -> None:
        self._plot.clear()
