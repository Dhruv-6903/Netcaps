"""Visualization tab with charts and network graph."""
import math
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                              QGroupBox, QLabel, QTabWidget)
from PyQt5.QtCore import Qt

try:
    import pyqtgraph as pg
    import numpy as np
    _PG_AVAILABLE = True
except ImportError:
    _PG_AVAILABLE = False

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False

from gui.widgets.chart_widget import ChartWidget
from gui.widgets.graph_widget import GraphWidget


class VisualizationTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        inner_tabs = QTabWidget()

        # Traffic spike chart
        spike_widget = QWidget()
        spike_lay = QVBoxLayout(spike_widget)
        self._spike_chart = ChartWidget("Traffic (Bytes/sec)")
        spike_lay.addWidget(self._spike_chart)
        inner_tabs.addTab(spike_widget, "Traffic Spike")

        # Protocol chart
        proto_widget = QWidget()
        proto_lay = QVBoxLayout(proto_widget)
        self._proto_chart = ChartWidget("Protocol Distribution")
        proto_lay.addWidget(self._proto_chart)
        inner_tabs.addTab(proto_widget, "Protocols")

        # Top Talkers
        talker_widget = QWidget()
        talker_lay = QVBoxLayout(talker_widget)
        self._talker_chart = ChartWidget("Top Talkers (Bytes)")
        talker_lay.addWidget(self._talker_chart)
        inner_tabs.addTab(talker_widget, "Top Talkers")

        # Network graph
        graph_widget = QWidget()
        graph_lay = QVBoxLayout(graph_widget)
        self._net_graph = GraphWidget()
        graph_lay.addWidget(self._net_graph)
        inner_tabs.addTab(graph_widget, "IP Communication Map")

        layout.addWidget(inner_tabs)

    def update_visualization(self, data: dict) -> None:
        bw_history = data.get("bandwidth_history", [])
        if bw_history:
            xs = [t for t, _ in bw_history]
            ys = [b for _, b in bw_history]
            if xs:
                x0 = xs[0]
                xs = [x - x0 for x in xs]
            self._spike_chart.update_line_chart(xs, ys, "#e94560")

        proto_dist = data.get("protocol_distribution", {})
        if proto_dist:
            categories = list(proto_dist.keys())
            values = [proto_dist[k] for k in categories]
            self._proto_chart.update_bar_chart(categories, values, "#0f3460")

        top_ips = data.get("top_src_ips", [])
        if top_ips:
            labels = [ip for ip, _ in top_ips[:10]]
            vals = [n for _, n in top_ips[:10]]
            self._talker_chart.update_bar_chart(labels, vals, "#e94560")

        sessions = data.get("sessions", [])
        if sessions:
            node_set = set()
            edges = []
            for s in sessions[:200]:
                src = s.get("src_ip", "")
                dst = s.get("dst_ip", "")
                if src and dst:
                    node_set.add(src)
                    node_set.add(dst)
                    edges.append((src, dst))
            self._net_graph.update_graph(list(node_set), edges)
