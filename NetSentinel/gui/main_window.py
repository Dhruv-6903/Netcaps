"""Main application window."""
import os
import sys
from datetime import datetime

import psutil
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                              QToolBar, QAction, QFileDialog, QComboBox,
                              QLineEdit, QPushButton, QTabWidget, QLabel,
                              QProgressBar, QMenuBar, QMenu, QDialog, QApplication,
                              QStatusBar as QSB, QMessageBox, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon

# Core modules
from core.pcap_loader import PcapLoader
from core.host_extractor import HostExtractor
from core.session_tracker import SessionTracker
from core.dns_parser import DnsParser
from core.credential_harvester import CredentialHarvester
from core.file_extractor import FileExtractor
from core.email_parser import EmailParser
from core.chat_parser import ChatParser
from core.alert_engine import AlertEngine
from core.tls_inspector import TlsInspector
from core.timeline_builder import TimelineBuilder
from core.stats_engine import StatsEngine
from core.traffic_classifier import TrafficClassifier
from core.anomaly_detector import AnomalyDetector
from core.port_scanner_detector import PortScannerDetector
from core.protocol_reassembler import ProtocolReassembler
from core.export_engine import ExportEngine
from core.live_capture import LiveCapture
from core.oui_lookup import OuiLookup

# GUI modules
from gui.tabs.hosts_tab import HostsTab
from gui.tabs.sessions_tab import SessionsTab
from gui.tabs.credentials_tab import CredentialsTab
from gui.tabs.files_tab import FilesTab
from gui.tabs.dns_tab import DnsTab
from gui.tabs.alerts_tab import AlertsTab
from gui.tabs.emails_tab import EmailsTab
from gui.tabs.chat_tab import ChatTab
from gui.tabs.timeline_tab import TimelineTab
from gui.tabs.stats_tab import StatsTab
from gui.tabs.visualization_tab import VisualizationTab
from gui.widgets.status_bar import StatusBar
from gui.widgets.badge_tab_bar import BadgeTabBar
from gui.widgets.filter_bar import FilterBar

from config import settings


class AnalysisWorker(QThread):
    """Worker thread for PCAP analysis."""

    progress = pyqtSignal(int, int)       # current, total
    packet_count_updated = pyqtSignal(int)
    hosts_updated = pyqtSignal(dict)
    sessions_updated = pyqtSignal(list)
    dns_updated = pyqtSignal(list)
    creds_updated = pyqtSignal(list)
    files_updated = pyqtSignal(list)
    emails_updated = pyqtSignal(list)
    chats_updated = pyqtSignal(dict)
    alerts_updated = pyqtSignal(list)
    timeline_updated = pyqtSignal(list)
    stats_updated = pyqtSignal(dict)
    finished = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, filepath: str, parent=None):
        super().__init__(parent)
        self.filepath = filepath
        self._total = 0

    def run(self) -> None:
        try:
            host_ext = HostExtractor()
            session_tracker = SessionTracker()
            dns_parser = DnsParser()
            cred_harvester = CredentialHarvester()
            tls_inspector = TlsInspector()
            stats_engine = StatsEngine()
            anomaly_detector = AnomalyDetector()
            port_scan_detector = PortScannerDetector()
            alert_engine = AlertEngine()
            timeline = TimelineBuilder()
            reassembler = ProtocolReassembler()
            file_extractor = FileExtractor()
            email_parser = EmailParser()
            chat_parser = ChatParser()
            oui = OuiLookup(settings.MANUF_PATH)
            classifier = TrafficClassifier()

            reassembler.register_handler(file_extractor.process_stream)
            reassembler.register_handler(email_parser.process_stream)
            reassembler.register_handler(chat_parser.process_stream)

            packets_window = []

            def on_packet(ts, buf, eth):
                host_ext.process_packet(ts, buf, eth)
                session_tracker.process_packet(ts, buf, eth)
                dns_parser.process_packet(ts, buf, eth)
                cred_harvester.process_packet(ts, buf, eth)
                tls_inspector.process_packet(ts, buf, eth)
                stats_engine.process_packet(ts, buf, eth)
                anomaly_detector.process_packet(ts, buf, eth)
                port_scan_detector.process_packet(ts, buf, eth)
                reassembler.process_packet(ts, buf, eth)
                packets_window.append((ts, "", ""))

            def on_progress(count):
                self.progress.emit(count, self._total)
                self.packet_count_updated.emit(count)

            loader = PcapLoader()
            self._total = 0
            # Count first
            from core.pcap_loader import _count_packets, _detect_format
            fmt = _detect_format(self.filepath)
            self._total = _count_packets(self.filepath, fmt)

            total = loader.load(self.filepath, {"packet": on_packet, "progress": on_progress})

            # Apply OUI vendor to hosts
            hosts = host_ext.hosts
            for ip, h in hosts.items():
                if h.get("mac") and not h.get("vendor"):
                    h["vendor"] = oui.lookup(h["mac"])

            # Run alert engine
            alert_engine.check_all(
                hosts,
                session_tracker.sessions,
                dns_parser.events,
                cred_harvester.credentials,
                file_extractor.files,
                packets_window,
            )

            # Build timeline
            for alert in alert_engine.alerts:
                ips = alert.get("related_ips", [])
                src = ips[0] if ips else ""
                dst = ips[1] if len(ips) > 1 else ""
                timeline.add_event(alert.get("timestamp"), "alert",
                                   alert.get("severity", "INFO"), src, dst,
                                   alert.get("description", ""))

            for cred in cred_harvester.credentials:
                timeline.add_event(cred.get("timestamp"), "credential", "HIGH",
                                   cred.get("src_ip", ""), cred.get("dst_ip", ""),
                                   f"{cred['protocol']} credential: {cred['username']}")

            for ev in dns_parser.events:
                if ev.get("tags"):
                    timeline.add_event(ev.get("timestamp"), "dns", "MEDIUM",
                                       ev.get("src_ip", ""), ev.get("dst_ip", ""),
                                       f"DNS: {ev['fqdn']} [{','.join(ev['tags'])}]")

            # Emit results
            self.hosts_updated.emit(hosts)
            self.sessions_updated.emit(session_tracker.sessions)
            self.dns_updated.emit(dns_parser.events)
            self.creds_updated.emit(cred_harvester.credentials)
            self.files_updated.emit(file_extractor.files)
            self.emails_updated.emit(email_parser.emails)
            self.chats_updated.emit(chat_parser.conversations)
            self.alerts_updated.emit(alert_engine.alerts)
            self.timeline_updated.emit(timeline.events)
            self.stats_updated.emit(stats_engine.stats)
            self.finished.emit(total)

        except Exception as e:
            import traceback
            self.error.emit(traceback.format_exc())


class MainWindow(QMainWindow):
    """NetSentinel main application window."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NetSentinel — Network Forensics")
        self.resize(1400, 900)

        self._worker = None
        self._live_capture = None
        self._packet_count = 0
        self._hosts_count = 0
        self._sessions_count = 0
        self._alerts_count = 0
        self._analysis_data = {}
        self._timeline_events = []

        self._build_ui()
        self._build_toolbar()
        self._build_menubar()
        self._connect_signals()

        # Badge update timer
        self._badge_timer = QTimer()
        self._badge_timer.timeout.connect(self._update_badges)
        self._badge_timer.start(500)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QVBoxLayout(central)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        # Filter bar
        filter_widget = QWidget()
        filter_widget.setFixedHeight(36)
        filter_lay = QHBoxLayout(filter_widget)
        filter_lay.setContentsMargins(6, 2, 6, 2)

        filter_lay.addWidget(QLabel("Interface:"))
        self._iface_combo = QComboBox()
        self._populate_interfaces()
        self._iface_combo.setMinimumWidth(150)
        filter_lay.addWidget(self._iface_combo)

        filter_lay.addWidget(QLabel("BPF Filter:"))
        self._bpf_input = QLineEdit()
        self._bpf_input.setPlaceholderText("e.g. tcp port 80")
        self._bpf_input.setMinimumWidth(200)
        filter_lay.addWidget(self._bpf_input)

        self._apply_btn = QPushButton("Apply")
        self._apply_btn.clicked.connect(self._apply_filter)
        filter_lay.addWidget(self._apply_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self._clear_filter)
        filter_lay.addWidget(self._clear_btn)
        filter_lay.addStretch()

        main_lay.addWidget(filter_widget)

        # Tab widget with badge tab bar
        self._tabs = QTabWidget()
        self._badge_bar = BadgeTabBar()
        self._tabs.setTabBar(self._badge_bar)

        # Create all tabs
        self._hosts_tab = HostsTab()
        self._sessions_tab = SessionsTab()
        self._creds_tab = CredentialsTab()
        self._files_tab = FilesTab()
        self._dns_tab = DnsTab()
        self._alerts_tab = AlertsTab()
        self._emails_tab = EmailsTab()
        self._chat_tab = ChatTab()
        self._timeline_tab = TimelineTab()
        self._viz_tab = VisualizationTab()
        self._stats_tab = StatsTab()

        self._tabs.addTab(self._hosts_tab, "Hosts")
        self._tabs.addTab(self._sessions_tab, "Sessions")
        self._tabs.addTab(self._creds_tab, "Credentials")
        self._tabs.addTab(self._files_tab, "Files")
        self._tabs.addTab(self._dns_tab, "DNS")
        self._tabs.addTab(self._alerts_tab, "Alerts")
        self._tabs.addTab(self._emails_tab, "Emails")
        self._tabs.addTab(self._chat_tab, "Chat")
        self._tabs.addTab(self._timeline_tab, "Timeline")
        self._tabs.addTab(self._viz_tab, "Visualization")
        self._tabs.addTab(self._stats_tab, "Stats")

        main_lay.addWidget(self._tabs)

        # Status bar
        self._status_bar = StatusBar()
        self.setStatusBar(None)  # disable default
        main_lay.addWidget(self._status_bar)

    def _build_toolbar(self) -> None:
        tb = self.addToolBar("Main")
        tb.setMovable(False)
        tb.setFixedHeight(48)

        title = QLabel("🛡 <b>NetSentinel</b>")
        title.setStyleSheet("font-size: 16px; color: #e94560; padding: 0 12px;")
        tb.addWidget(title)

        self._load_action = QAction("📂 Load PCAP", self)
        self._load_action.triggered.connect(self.load_pcap)
        tb.addAction(self._load_action)

        self._start_capture_action = QAction("▶ Start Capture", self)
        self._start_capture_action.triggered.connect(self.start_capture)
        tb.addAction(self._start_capture_action)

        self._stop_capture_action = QAction("■ Stop Capture", self)
        self._stop_capture_action.triggered.connect(self.stop_capture)
        self._stop_capture_action.setEnabled(False)
        tb.addAction(self._stop_capture_action)

        tb.addSeparator()

        export_btn = QPushButton("📤 Export ▾")
        export_btn.clicked.connect(self._show_export_menu)
        tb.addWidget(export_btn)

        tb.addSeparator()

        settings_action = QAction("⚙ Settings", self)
        settings_action.triggered.connect(self._open_settings)
        tb.addAction(settings_action)

    def _build_menubar(self) -> None:
        mb = self.menuBar()

        file_menu = mb.addMenu("File")
        open_act = QAction("Open PCAP...", self)
        open_act.setShortcut("Ctrl+O")
        open_act.triggered.connect(self.load_pcap)
        file_menu.addAction(open_act)

        file_menu.addSeparator()
        quit_act = QAction("Quit", self)
        quit_act.setShortcut("Ctrl+Q")
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        view_menu = mb.addMenu("View")
        search_act = QAction("Global Search...", self)
        search_act.setShortcut("Ctrl+F")
        search_act.triggered.connect(self._global_search)
        view_menu.addAction(search_act)

    def _connect_signals(self) -> None:
        pass

    def _populate_interfaces(self) -> None:
        self._iface_combo.clear()
        try:
            for iface in psutil.net_if_stats().keys():
                self._iface_combo.addItem(iface)
        except Exception:
            self._iface_combo.addItem("eth0")

    def load_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP/PCAPNG", "",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if not path:
            return

        self._status_bar.set_source(os.path.basename(path))
        self._status_bar.set_progress(0, 100)

        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait()

        self._worker = AnalysisWorker(path, self)
        self._worker.progress.connect(self._on_progress)
        self._worker.packet_count_updated.connect(self._on_pkt_count)
        self._worker.hosts_updated.connect(self._on_hosts)
        self._worker.sessions_updated.connect(self._on_sessions)
        self._worker.dns_updated.connect(self._on_dns)
        self._worker.creds_updated.connect(self._on_creds)
        self._worker.files_updated.connect(self._on_files)
        self._worker.emails_updated.connect(self._on_emails)
        self._worker.chats_updated.connect(self._on_chats)
        self._worker.alerts_updated.connect(self._on_alerts)
        self._worker.timeline_updated.connect(self._on_timeline)
        self._worker.stats_updated.connect(self._on_stats)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def start_capture(self) -> None:
        iface = self._iface_combo.currentText()
        if not iface:
            return
        bpf = self._bpf_input.text().strip()

        self._live_capture = LiveCapture()
        self._live_capture.set_packet_callback(self._on_live_packet)
        try:
            self._live_capture.start(iface, bpf)
        except Exception as e:
            QMessageBox.warning(self, "Capture Error", str(e))
            return

        self._start_capture_action.setEnabled(False)
        self._stop_capture_action.setEnabled(True)
        self._status_bar.set_live(True)
        self._status_bar.set_source(f"Live: {iface}")

    def stop_capture(self) -> None:
        if self._live_capture:
            self._live_capture.stop()
            self._live_capture = None
        self._start_capture_action.setEnabled(True)
        self._stop_capture_action.setEnabled(False)
        self._status_bar.set_live(False)

    def _on_live_packet(self, raw: bytes) -> None:
        self._packet_count += 1
        self._status_bar.update_counts(self._packet_count, self._hosts_count,
                                       self._sessions_count, self._alerts_count)

    def _on_progress(self, current: int, total: int) -> None:
        if total > 0:
            self._status_bar.set_progress(current, total)

    def _on_pkt_count(self, count: int) -> None:
        self._packet_count = count
        self._status_bar.update_counts(count, self._hosts_count,
                                       self._sessions_count, self._alerts_count)

    def _on_hosts(self, hosts: dict) -> None:
        self._hosts_count = len(hosts)
        self._analysis_data["hosts"] = hosts
        self._hosts_tab.update_hosts(hosts)
        self._update_status()

    def _on_sessions(self, sessions: list) -> None:
        self._sessions_count = len(sessions)
        self._analysis_data["sessions"] = sessions
        self._sessions_tab.update_sessions(sessions)
        self._update_status()

    def _on_dns(self, events: list) -> None:
        self._analysis_data["dns_events"] = events
        self._dns_tab.update_dns(events)

    def _on_creds(self, creds: list) -> None:
        self._analysis_data["credentials"] = creds
        self._creds_tab.update_credentials(creds)

    def _on_files(self, files: list) -> None:
        self._analysis_data["files"] = files
        self._files_tab.update_files(files)

    def _on_emails(self, emails: list) -> None:
        self._analysis_data["emails"] = emails
        self._emails_tab.update_emails(emails)

    def _on_chats(self, chats: dict) -> None:
        self._analysis_data["chats"] = chats
        self._chat_tab.update_chats(chats)

    def _on_alerts(self, alerts: list) -> None:
        self._alerts_count = len(alerts)
        self._analysis_data["alerts"] = alerts
        self._alerts_tab.update_alerts(alerts)
        self._update_status()

    def _on_timeline(self, events: list) -> None:
        self._timeline_events = events
        self._analysis_data["timeline"] = events
        self._timeline_tab.update_timeline(events)

        from core.timeline_builder import TimelineBuilder
        tb = TimelineBuilder()
        narrative = tb.build_attack_narrative(self._analysis_data.get("alerts", []))
        self._timeline_tab.set_narrative(narrative)

    def _on_stats(self, stats: dict) -> None:
        self._analysis_data["stats"] = stats
        self._stats_tab.update_stats(stats)

        viz_data = {
            "bandwidth_history": stats.get("bandwidth_history", []),
            "protocol_distribution": stats.get("protocol_distribution", {}),
            "top_src_ips": stats.get("top_src_ips", []),
            "sessions": self._analysis_data.get("sessions", []),
        }
        self._viz_tab.update_visualization(viz_data)

    def _on_finished(self, total: int) -> None:
        self._packet_count = total
        self._status_bar.set_progress(total, total)
        self._update_status()

    def _on_error(self, msg: str) -> None:
        QMessageBox.critical(self, "Analysis Error", msg[:1000])

    def _update_status(self) -> None:
        self._status_bar.update_counts(self._packet_count, self._hosts_count,
                                       self._sessions_count, self._alerts_count)

    def _update_badges(self) -> None:
        counts = {
            0: self._hosts_count,
            1: self._sessions_count,
            2: len(self._analysis_data.get("credentials", [])),
            3: len(self._analysis_data.get("files", [])),
            4: len(self._analysis_data.get("dns_events", [])),
            5: self._alerts_count,
            6: len(self._analysis_data.get("emails", [])),
            7: len(self._analysis_data.get("chats", {})),
        }
        for idx, count in counts.items():
            if count > 0:
                self._badge_bar.set_badge_count(idx, count)

    def _show_export_menu(self) -> None:
        menu = QMenu(self)
        csv_act = QAction("Export CSV", self)
        csv_act.triggered.connect(self._export_csv)
        menu.addAction(csv_act)

        json_act = QAction("Export JSON", self)
        json_act.triggered.connect(self._export_json)
        menu.addAction(json_act)

        html_act = QAction("Export HTML Report", self)
        html_act.triggered.connect(self._export_html)
        menu.addAction(html_act)

        zip_act = QAction("Export Files ZIP", self)
        zip_act.triggered.connect(self._export_zip)
        menu.addAction(zip_act)

        timeline_act = QAction("Export Timeline CSV", self)
        timeline_act.triggered.connect(self._export_timeline)
        menu.addAction(timeline_act)

        btn = self.sender()
        menu.exec_(btn.mapToGlobal(btn.rect().bottomLeft()))

    def _export_csv(self) -> None:
        out_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory",
                                                    settings.REPORTS_DIR)
        if out_dir:
            ExportEngine().export_csv(self._analysis_data, out_dir)
            QMessageBox.information(self, "Export", f"CSV files saved to:\n{out_dir}")

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "report.json",
                                               "JSON (*.json)")
        if path:
            ExportEngine().export_json(self._analysis_data, path)

    def _export_html(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save HTML Report", "report.html",
                                               "HTML (*.html)")
        if path:
            ExportEngine().export_html(self._analysis_data, path)

    def _export_zip(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save ZIP", "files.zip",
                                               "ZIP (*.zip)")
        if path:
            ExportEngine().export_files_zip(self._analysis_data.get("files", []), path)

    def _export_timeline(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Timeline CSV", "timeline.csv",
                                               "CSV (*.csv)")
        if path:
            ExportEngine().export_timeline_csv(self._timeline_events, path)

    def _apply_filter(self) -> None:
        pass  # BPF filter applied on capture start

    def _clear_filter(self) -> None:
        self._bpf_input.clear()

    def _open_settings(self) -> None:
        QMessageBox.information(self, "Settings",
                                "Edit config/settings.py to configure API keys and paths.")

    def _global_search(self) -> None:
        from PyQt5.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(self, "Global Search", "Search all data:")
        if ok and text:
            self._tabs.setCurrentIndex(0)
