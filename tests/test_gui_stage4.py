import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from PySide6.QtCore import QThread, Qt
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, wrpcap

import main
from capture_engine import CaptureWorker
from domain_models import AnalysisResult, AnalysisStats, DomainEvidence, EvidenceSource
from main import SnifferWindow
from packet_filter import parse_filter
from packet_model import PacketTableModel
from helpers import SnifferFactory, app, wait_until


def _packets():
    query = Ether(src="30:7b:ac:69:38:02", dst="9c:67:d6:c8:2f:0d") / IP(
        src="10.0.0.2", dst="8.8.8.8"
    ) / UDP(sport=53000, dport=53) / DNS(id=9, qd=DNSQR(qname="www.example.test", qtype="A"))
    response = Ether(src="9c:67:d6:c8:2f:0d", dst="30:7b:ac:69:38:02") / IP(
        src="8.8.8.8", dst="10.0.0.2"
    ) / UDP(sport=53, dport=53000) / DNS(
        id=9,
        qr=1,
        qd=DNSQR(qname="www.example.test", qtype="A"),
        an=DNSRR(rrname="www.example.test", type="A", ttl=30, rdata="203.0.113.10"),
    )
    query.time, response.time = 100.0, 100.1
    return [query, response]


class _ControlledAnalysisWorker(QThread):
    """仅用于 GUI 生命周期测试的可控分析线程。"""

    def __init__(self, snapshot, gate, mode, parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self.gate = gate
        self.mode = mode
        self.cancel_event = Event()
        self.result = None
        self.error = ""
        self.cancelled = False

    def request_cancel(self):
        self.cancel_event.set()

    def run(self):
        self.gate.wait(5)
        if self.mode == "cancel":
            self.cancelled = True
            return
        self.result = AnalysisResult(
            generation=self.snapshot.generation,
            stats=AnalysisStats(
                query_count=99,
                response_count=99,
                matched_transaction_count=99,
                unmatched_query_count=99,
                unique_domain_count=99,
            ),
        )


class Stage4ModelTests(unittest.TestCase):
    def test_analysis_adds_domain_columns_without_breaking_empty_model(self):
        model = PacketTableModel()
        self.assertEqual(model.columnCount(), 8)
        result = AnalysisResult(
            generation=0,
            rows={0: (DomainEvidence("www.example.test", EvidenceSource.HTTP_HOST, 0),)},
        )
        model.append_batch([_packets()[0]])
        model.set_analysis(result)
        self.assertEqual(model.columnCount(), 10)
        self.assertEqual(model.data(model.index(0, 8)), "www.example.test")
        self.assertEqual(model.data(model.index(0, 9)), "HTTP Host")


class Stage4GuiTests(unittest.TestCase):
    def setUp(self):
        app()
        self.window = SnifferWindow()

    def tearDown(self):
        if self.window.analysis_thread is not None:
            self.window.analysis_thread.request_cancel()
            self.window.analysis_thread.wait(1000)
            self.window.analysis_thread = None
        if self.window.capture_thread is not None:
            self.window.stop_capture()
            wait_until(lambda: self.window.capture_thread is None)
        self.window.close()
        self.window.deleteLater()

    def _analyze(self):
        """发布合成 DNS 查询/响应并等待一次成功分析。"""
        self.window.source_model.append_batch(_packets())
        self.window.start_domain_analysis()
        self.assertTrue(wait_until(lambda: self.window.analysis_thread is None))
        self.assertIsNotNone(self.window.analysis_result)

    def test_offline_analysis_publishes_columns_and_domain_filter(self):
        self.window.source_model.append_batch(_packets())
        self.window.start_domain_analysis()
        self.assertTrue(wait_until(lambda: self.window.analysis_thread is None))
        self.assertIsNotNone(self.window.analysis_result)
        self.assertEqual(self.window.source_model.columnCount(), 10)
        self.window.domain_edit.setText("www.example.test")
        self.assertTrue(self.window.apply_display_filter())
        self.assertEqual(self.window.displayed_packets, 2)
        self.window.domain_edit.setText("missing.example.test")
        self.assertTrue(self.window.apply_display_filter())
        self.assertEqual(self.window.displayed_packets, 0)

    def test_cancel_does_not_commit_partial_result(self):
        self.window.source_model.append_batch(_packets())
        self.window.start_domain_analysis()
        if self.window.analysis_thread is not None:
            self.window.stop_capture()
        self.assertTrue(wait_until(lambda: self.window.analysis_thread is None))
        self.assertIsNone(self.window.analysis_result)
        self.assertIn("尚未分析", self.window.analysis_stats_label.text())

    def test_analysis_stats_are_shown_and_unchanged_by_domain_filter(self):
        self.assertEqual(self.window.analysis_stats_label.text(), "DNS统计：尚未分析")
        self._analyze()
        stats_text = self.window.analysis_stats_label.text()
        for fragment in (
            "查询 1",
            "响应 1",
            "匹配事务 1",
            "未匹配查询 0",
            "唯一直接域名 1",
        ):
            self.assertIn(fragment, stats_text)
        self.window.domain_edit.setText("www.example.test")
        self.assertTrue(self.window.apply_display_filter())
        self.assertEqual(self.window.analysis_stats_label.text(), stats_text)

    def test_clear_packets_resets_analysis_stats(self):
        self._analyze()
        self.window.clear_packets()
        self.assertIsNone(self.window.analysis_result)
        self.assertEqual(self.window.analysis_stats_label.text(), "DNS统计：尚未分析")

    def test_successful_import_resets_previous_analysis_stats(self):
        self._analyze()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "imported.pcap"
            wrpcap(str(path), _packets())
            self.window.open_path(str(path))
            self.assertTrue(wait_until(lambda: self.window.load_thread is None))
        self.assertIsNone(self.window.analysis_result)
        self.assertEqual(self.window.analysis_stats_label.text(), "DNS统计：尚未分析")

    def test_new_capture_invalidates_analysis_stats_without_real_npcap(self):
        self._analyze()
        if not self.window.interface_box.count():
            self.window.interface_box.addItem("测试网卡", "fake0")
        interface = str(self.window.interface_box.currentData() or "fake0")
        self.window._capture_interface = interface
        factory = SnifferFactory()
        with patch.object(
            main,
            "CaptureWorker",
            lambda device, buffer: CaptureWorker(device, buffer, factory),
        ):
            self.window.start_capture()
            self.assertEqual(self.window.analysis_stats_label.text(), "DNS统计：尚未分析")
            self.assertIsNone(self.window.analysis_result)
            self.assertTrue(wait_until(lambda: factory.instances and factory.instances[0].ready.is_set()))
            self.window.stop_capture()
            self.assertTrue(wait_until(lambda: self.window.capture_thread is None))

    def test_cancelled_analysis_clears_stats_without_publishing_result(self):
        gate = Event()
        worker_factory = lambda snapshot, parent=None: _ControlledAnalysisWorker(
            snapshot, gate, "cancel", parent
        )
        self.window.source_model.append_batch(_packets())
        try:
            with patch.object(main, "DomainAnalysisWorker", worker_factory):
                self.window.start_domain_analysis()
                self.assertIsNotNone(self.window.analysis_thread)
                self.window.stop_capture()
                gate.set()
                self.assertTrue(wait_until(lambda: self.window.analysis_thread is None))
        finally:
            gate.set()
        self.assertIsNone(self.window.analysis_result)
        self.assertEqual(self.window.analysis_stats_label.text(), "DNS统计：尚未分析")

    def test_stale_analysis_result_is_not_committed_or_displayed(self):
        gate = Event()
        worker_factory = lambda snapshot, parent=None: _ControlledAnalysisWorker(
            snapshot, gate, "stale", parent
        )
        self.window.source_model.append_batch(_packets())
        try:
            with patch.object(main, "DomainAnalysisWorker", worker_factory):
                self.window.start_domain_analysis()
                self.assertIsNotNone(self.window.analysis_thread)
                self.window._invalidate_analysis()
                gate.set()
                self.assertTrue(wait_until(lambda: self.window.analysis_thread is None))
        finally:
            gate.set()
        self.assertIsNone(self.window.analysis_result)
        self.assertEqual(self.window.analysis_stats_label.text(), "DNS统计：尚未分析")
        self.assertIn("过期", self.window.notice)


if __name__ == "__main__":
    unittest.main()
