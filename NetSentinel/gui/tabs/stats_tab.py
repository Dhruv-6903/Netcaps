"""Statistics tab."""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                              QTableWidgetItem, QHeaderView, QLabel, QSplitter,
                              QGroupBox, QGridLayout)
from PyQt5.QtCore import Qt


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


class StatsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Summary row
        summary = QHBoxLayout()
        self._metrics = {}
        for key in ("Total Packets", "Total Bytes", "Packets/sec", "Avg Pkt Size", "Protocols"):
            box = QGroupBox(key)
            bl = QVBoxLayout(box)
            lbl = QLabel("0")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #e94560;")
            bl.addWidget(lbl)
            summary.addWidget(box)
            self._metrics[key] = lbl
        layout.addLayout(summary)

        # Tables row
        tables_splitter = QSplitter(Qt.Horizontal)

        # Protocol distribution
        proto_group = QGroupBox("Protocol Distribution")
        pl = QVBoxLayout(proto_group)
        self._proto_table = self._make_table(["Protocol", "Packets", "%"])
        pl.addWidget(self._proto_table)
        tables_splitter.addWidget(proto_group)

        # Top src IPs
        src_group = QGroupBox("Top Source IPs")
        sl = QVBoxLayout(src_group)
        self._src_table = self._make_table(["IP", "Packets"])
        sl.addWidget(self._src_table)
        tables_splitter.addWidget(src_group)

        # Top dst IPs
        dst_group = QGroupBox("Top Destination IPs")
        dl = QVBoxLayout(dst_group)
        self._dst_table = self._make_table(["IP", "Packets"])
        dl.addWidget(self._dst_table)
        tables_splitter.addWidget(dst_group)

        # Top ports
        port_group = QGroupBox("Top Ports")
        portl = QVBoxLayout(port_group)
        self._port_table = self._make_table(["Port", "Count"])
        portl.addWidget(self._port_table)
        tables_splitter.addWidget(port_group)

        layout.addWidget(tables_splitter)

    def _make_table(self, headers: list) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.setAlternatingRowColors(True)
        return t

    def update_stats(self, stats: dict) -> None:
        total_pkt = stats.get("total_packets", 0)
        total_bytes = stats.get("total_bytes", 0)
        pps = stats.get("packets_per_sec", 0)
        avg_size = stats.get("avg_packet_size", 0)
        proto_dist = stats.get("protocol_distribution", {})

        self._metrics["Total Packets"].setText(f"{total_pkt:,}")
        self._metrics["Total Bytes"].setText(_fmt_bytes(total_bytes))
        self._metrics["Packets/sec"].setText(f"{pps:.1f}")
        self._metrics["Avg Pkt Size"].setText(f"{avg_size:.0f} B")
        self._metrics["Protocols"].setText(str(len(proto_dist)))

        # Protocol table
        self._populate_table(self._proto_table,
                             [[p, str(n), f"{100*n/max(total_pkt,1):.1f}%"]
                              for p, n in sorted(proto_dist.items(), key=lambda x: -x[1])])

        # IP tables
        self._populate_table(self._src_table,
                             [[ip, str(n)] for ip, n in stats.get("top_src_ips", [])])
        self._populate_table(self._dst_table,
                             [[ip, str(n)] for ip, n in stats.get("top_dst_ips", [])])
        self._populate_table(self._port_table,
                             [[str(p), str(n)] for p, n in stats.get("top_dst_ports", [])])

    def _populate_table(self, table: QTableWidget, rows: list) -> None:
        table.setRowCount(0)
        for row_data in rows:
            row = table.rowCount()
            table.insertRow(row)
            for col, val in enumerate(row_data):
                table.setItem(row, col, QTableWidgetItem(val))
