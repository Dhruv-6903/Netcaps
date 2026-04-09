"""Network graph widget using networkx + pyqtgraph."""
import math
import networkx as nx
import pyqtgraph as pg
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import pyqtSignal
import numpy as np


class GraphWidget(QWidget):
    """Render a directed network graph using pyqtgraph GraphItem."""

    node_clicked = pyqtSignal(str)
    edge_clicked = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._graph = nx.DiGraph()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        pg.setConfigOption("background", "#1a1a2e")
        pg.setConfigOption("foreground", "#eaeaea")

        self._view = pg.GraphicsLayoutWidget()
        self._plot = self._view.addPlot()
        self._plot.setAspectLocked(True)
        self._plot.hideAxis("left")
        self._plot.hideAxis("bottom")

        self._graph_item = pg.GraphItem()
        self._plot.addItem(self._graph_item)

        layout.addWidget(self._view)

    def update_graph(self, nodes: list, edges: list) -> None:
        """
        nodes: list of node IDs (strings)
        edges: list of (src, dst) tuples
        """
        self._graph.clear()
        self._graph.add_nodes_from(nodes)
        self._graph.add_edges_from(edges)

        if not nodes:
            self._graph_item.setData(pos=np.array([[0, 0]]), adj=np.array([[0, 0]]),
                                     size=10, pxMode=True)
            return

        # Layout
        try:
            pos = nx.spring_layout(self._graph, seed=42)
        except Exception:
            n = len(nodes)
            pos = {node: (math.cos(2 * math.pi * i / n) * 100,
                           math.sin(2 * math.pi * i / n) * 100)
                   for i, node in enumerate(nodes)}

        node_list = list(self._graph.nodes())
        node_idx = {n: i for i, n in enumerate(node_list)}
        positions = np.array([[pos[n][0] * 200, pos[n][1] * 200] for n in node_list])

        adj_list = []
        for src, dst in self._graph.edges():
            if src in node_idx and dst in node_idx:
                adj_list.append([node_idx[src], node_idx[dst]])

        adj = np.array(adj_list) if adj_list else np.empty((0, 2), dtype=int)

        self._node_list = node_list
        self._graph_item.setData(
            pos=positions,
            adj=adj,
            size=12,
            pxMode=True,
            symbol="o",
            symbolPen=pg.mkPen("#e94560", width=1),
            symbolBrush=pg.mkBrush("#0f3460"),
            pen=pg.mkPen("#2a2a4a", width=1),
        )

    def clear(self) -> None:
        self._graph.clear()
        self._graph_item.setData(pos=np.array([[0, 0]]))
