"""阶段 5 动态列、后台 TCP 分析及数据集生命周期的离线 GUI 测试。"""

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

from helpers import SnifferFactory, app, wait_until
from PySide6.QtCore import QThread, QTimer
from PySide6.QtTest import QTest
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, rdpcap, wrpcap

import main
import stream_ui
from capture_engine import CaptureWorker
from domain_models import AnalysisResult
from examples.make_stream_demo import build_demo_packets
from packet_model import PacketTableModel
from stream_analysis import analyze_streams
from stream_models import StreamAnalysisResult


class ControlledStreamWorker(QThread):
    """即使收到取消也返回结果，以验证窗口不会提交迟到结果。"""

    def __init__(self, snapshot, gate, mode="success", parent=None):
        super().__init__(parent)
        self.snapshot, self.gate, self.mode = snapshot, gate, mode
        self.cancel_event = Event()
        self.result, self.error, self.cancelled, self.progress = None, "", False, 12

    def request_cancel(self):
        self.cancel_event.set()

    def run(self):
        self.gate.wait(5)
        if self.mode == "failure":
            self.error = "测试分析失败"
            return
        result = analyze_streams(self.snapshot)
        changes = {
            "generation": {"generation": result.generation + 1},
            "dataset": {"dataset_id": "different-file.pcap"},
            "identity": {"packet_identity": tuple(-1 for _ in result.packet_identity)},
        }
        self.result = replace(result, **changes.get(self.mode, {}))


class ControlledLoadWorker(QThread):
    """只在取消后退出的读取替身，不访问磁盘。"""

    def __init__(self, path, max_packets, max_bytes):
        super().__init__()
        self.gate = Event()
        self.error, self.packets, self.cancelled = "", [], False

    def request_cancel(self):
        self.cancelled = True
        self.gate.set()

    def run(self):
        self.gate.wait(5)


def dns_packets():
    """构造独立 DNS 查询响应，供两个分析结果共存测试使用。"""
    ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    query = ethernet / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(
        sport=53000, dport=53
    ) / DNS(id=17, qd=DNSQR(qname="dns.stage5.example.test"))
    reply = ethernet / IP(src="192.0.2.53", dst="192.0.2.1") / UDP(
        sport=53, dport=53000
    ) / DNS(id=17, qr=1, qd=DNSQR(qname="dns.stage5.example.test"),
            an=DNSRR(rrname="dns.stage5.example.test", rdata="203.0.113.10", ttl=30))
    query.time, reply.time = 1800000001.0, 1800000001.1
    return [query, reply]


class Stage5ModelTests(unittest.TestCase):
    def test_dynamic_columns_coexist_and_non_tcp_cells_are_empty(self):
        app()
        model = PacketTableModel()
        model.append_batch(dns_packets())
        domains = AnalysisResult(0)
        streams = StreamAnalysisResult()
        self.assertEqual(model.columnCount(), 8)
        model.set_analysis(domains)
        self.assertEqual(model.columnCount(), 10)
        model.set_stream_analysis(streams)
        self.assertEqual(model.columnCount(), 13)
        self.assertEqual([model.data(model.index(0, c)) for c in range(10, 13)], ["", "", ""])
        model.set_analysis(None)
        self.assertEqual(model.columnCount(), 11)
        self.assertIs(model.stream_result, streams)
        model.append_batch([])
        self.assertIs(model.stream_result, streams)
        model.append_batch(dns_packets())
        self.assertIsNone(model.stream_result)
        self.assertEqual(model.columnCount(), 8)
        model.set_stream_analysis(streams)
        model.set_analysis(domains)
        model.set_stream_analysis(None)
        self.assertIs(model.analysis_result, domains)
        model.set_stream_analysis(streams)
        model.clear()
        self.assertEqual(model.columnCount(), 8)


class Stage5GuiTests(unittest.TestCase):
    def setUp(self):
        app()
        interfaces = [SimpleNamespace(network_name="fake0", name="测试网卡", ip="192.0.2.1")]
        for patcher in (
            patch.object(main, "get_interfaces", return_value=interfaces),
            patch.object(main, "conf", SimpleNamespace(iface="fake0", loopback_name="fake0")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.window = main.SnifferWindow()
        self.gates = []

    def tearDown(self):
        for gate in self.gates:
            gate.set()
        for name in ("stream_thread", "analysis_thread", "load_thread"):
            worker = getattr(self.window, name)
            if worker is not None:
                worker.request_cancel()
        if self.window.capture_thread is not None:
            self.window.stop_capture()
        if not self.window.packet_timer.isActive():
            self.window.packet_timer.start(10)
        self.assertTrue(wait_until(lambda: not self.window.is_busy(), timeout=8))
        self.window.close()
        self.window.deleteLater()
        QTest.qWait(10)

    def offer(self, packets=None):
        """通过缓存交付数据，让模型和保留计数保持一致。"""
        for packet in build_demo_packets() if packets is None else packets:
            self.window.buffer.offer(packet)
        self.window.flush_pending_packets()

    def analyze(self, offer=True):
        """点击真实按钮并等待真实后台 Worker 完成。"""
        if offer:
            self.offer()
        self.window.stream_button.click()
        self.assertTrue(wait_until(lambda: self.window.stream_thread is None, timeout=8))
        self.assertIsNotNone(self.window.stream_result)
        return self.window.stream_result

    def controlled(self, mode="success"):
        """启动受门控线程，调用者通过返回的 Event 解除阻塞。"""
        gate = Event()
        self.gates.append(gate)
        factory = lambda snapshot, parent=None: ControlledStreamWorker(snapshot, gate, mode, parent)
        with patch.object(stream_ui, "StreamAnalysisWorker", factory):
            self.window.start_stream_analysis()
        return gate, self.window.stream_thread

    def domain_analysis(self):
        self.window.start_domain_analysis()
        self.assertTrue(wait_until(lambda: self.window.analysis_thread is None, timeout=8))
        self.assertIsNotNone(self.window.analysis_result)

    def assert_result_preserved(self, result, label):
        self.assertIs(self.window.stream_result, result)
        self.assertIs(self.window.source_model.stream_result, result)
        self.assertIs(self.window.stream_controller.result, result)
        self.assertEqual(self.window.stream_status_label.text(), label)

    def test_demo_button_runs_five_streams_with_two_domains(self):
        result = self.analyze()
        self.assertEqual(len(self.window.packets), 31)
        self.assertEqual(len(result.flows), 5)
        self.assertEqual({name for flow in result.flows for name in flow.domains},
                         {"www.stage5.example.test", "tls.stage5.example.test"})
        self.assertEqual(self.window.source_model.columnCount(), 11)
        self.assertIn("5 条", self.window.stream_status_label.text())
        self.assertIn("2 个", self.window.stream_status_label.text())
        self.assertFalse(self.window.is_busy())

    def test_domain_statistics_and_filter_survive_stream_analysis(self):
        self.offer(build_demo_packets() + dns_packets())
        self.domain_analysis()
        self.assertEqual(self.window.source_model.columnCount(), 10)
        domain_result, stats = self.window.analysis_result, self.window.analysis_stats_label.text()
        self.assertIn("查询 1", stats)
        self.window.domain_edit.setText("dns.stage5.example.test")
        self.assertTrue(self.window.apply_display_filter())
        self.assertEqual(self.window.displayed_packets, 2)
        self.analyze(offer=False)
        self.assertEqual(self.window.source_model.columnCount(), 13)
        self.assertEqual(self.window.displayed_packets, 2)
        self.assertIs(self.window.analysis_result, domain_result)
        self.assertEqual(self.window.analysis_stats_label.text(), stats)
        stream_result = self.window.stream_result
        self.domain_analysis()
        self.assertIs(self.window.stream_result, stream_result)
        self.assertEqual(self.window.source_model.columnCount(), 13)
        self.assertEqual(self.window.displayed_packets, 2)

    def test_filtered_selection_maps_to_source_flow_and_raw_packet(self):
        result = self.analyze()
        self.window.port_edit.setText("51002")
        self.assertTrue(self.window.apply_display_filter())
        index = self.window.proxy_model.mapToSource(self.window.proxy_model.index(0, 0))
        source_row = index.row()
        self.assertEqual(source_row, 9)
        self.window.packet_table.selectRow(0)
        QTest.qWait(10)
        detail = self.window.detail_text.toPlainText()
        self.assertIn("流 #2", detail)
        self.assertIn("tls.stage5.example.test", detail)
        self.assertIn("#10", detail)
        self.assertIn(bytes(self.window.packets[source_row]).hex(" "), detail)
        self.assertEqual(result.row_text(source_row)[0], "2")

    def test_cancel_keeps_previous_result_and_disables_conflicting_actions(self):
        old = self.analyze()
        label = self.window.stream_status_label.text()
        gate, worker = self.controlled()
        for button in (self.window.stream_button, self.window.analyze_button,
                       self.window.open_button, self.window.save_button, self.window.clear_button):
            self.assertFalse(button.isEnabled())
        self.assertTrue(self.window.stop_button.isEnabled())
        self.window.stop_button.click()
        self.assertTrue(worker.cancel_event.is_set())
        gate.set()
        self.assertTrue(wait_until(lambda: self.window.stream_thread is None))
        self.assert_result_preserved(old, label)
        self.assertIn("已取消", self.window.notice)

    def test_cancel_after_worker_finishes_but_before_commit_still_rejects(self):
        old = self.analyze()
        label = self.window.stream_status_label.text()
        self.window.packet_timer.stop()
        gate, worker = self.controlled()
        gate.set()
        self.assertTrue(worker.wait(3000))
        self.assertIsNotNone(worker.result)
        self.window.stop_capture()
        self.window.finish_stream_analysis()
        self.assert_result_preserved(old, label)
        self.assertIn("已取消", self.window.notice)

    def test_analysis_failure_preserves_previous_result(self):
        old = self.analyze()
        label = self.window.stream_status_label.text()
        gate, _worker = self.controlled("failure")
        gate.set()
        self.assertTrue(wait_until(lambda: self.window.stream_thread is None))
        self.assert_result_preserved(old, label)
        self.assertEqual(self.window.state, "error")

    def test_worker_creation_failure_does_not_leave_busy_state(self):
        old = self.analyze()
        label = self.window.stream_status_label.text()
        with patch.object(stream_ui, "StreamAnalysisWorker", side_effect=RuntimeError("测试启动失败")):
            self.window.start_stream_analysis()
        self.assertFalse(self.window.is_busy())
        self.assert_result_preserved(old, label)
        self.assertIn("测试启动失败", self.window.notice)

    def test_worker_start_failure_does_not_leave_thread_reference(self):
        old = self.analyze()
        label = self.window.stream_status_label.text()

        class StartFailureWorker(ControlledStreamWorker):
            def start(self):
                raise RuntimeError("测试线程启动失败")

        factory = lambda snapshot, parent=None: StartFailureWorker(snapshot, Event(), parent=parent)
        with patch.object(stream_ui, "StreamAnalysisWorker", factory):
            self.window.start_stream_analysis()
        self.assertIsNone(self.window.stream_thread)
        self.assertFalse(self.window.is_busy())
        self.assert_result_preserved(old, label)
        self.assertIn("测试线程启动失败", self.window.notice)

    def test_ten_thousand_packets_can_be_cancelled_from_gui_heartbeat(self):
        self.window.limit_box.setValue(10000)
        demo = build_demo_packets()
        samples = demo[:3] + [demo[4]] * 9997
        for offset in range(0, len(samples), 250):
            self.offer(samples[offset:offset + 250])
        self.assertEqual(len(self.window.packets), 10000)
        beats = []
        heartbeat = QTimer(self.window)
        heartbeat.setSingleShot(True)

        def cancel_on_heartbeat():
            beats.append(True)
            self.window.stop_capture()

        heartbeat.timeout.connect(cancel_on_heartbeat)
        self.window.start_stream_analysis()
        heartbeat.start(1)
        self.assertTrue(wait_until(lambda: self.window.stream_thread is None, timeout=8))
        heartbeat.stop()
        self.assertTrue(beats)
        self.assertIsNone(self.window.stream_result)
        self.assertIn("已取消", self.window.notice)
        self.assertEqual(len(self.window.packets), 10000)

    def test_stale_result_metadata_is_rejected(self):
        self.offer()
        for mode in ("generation", "dataset", "identity"):
            with self.subTest(mode=mode):
                gate, _worker = self.controlled(mode)
                gate.set()
                self.assertTrue(wait_until(lambda: self.window.stream_thread is None))
                self.assertIsNone(self.window.stream_result)
                self.assertEqual(self.window.source_model.columnCount(), 8)
                self.assertIn("过期", self.window.notice)

    def test_changed_packet_identity_rejects_old_snapshot(self):
        self.offer()
        gate, _worker = self.controlled()
        self.window.source_model.packets[0] = self.window.packets[0].copy()
        gate.set()
        self.assertTrue(wait_until(lambda: self.window.stream_thread is None))
        self.assertIsNone(self.window.stream_result)
        self.assertIn("过期", self.window.notice)

    def test_changed_dataset_and_generation_reject_old_snapshot(self):
        self.offer()
        for field in ("dataset", "generation"):
            with self.subTest(field=field):
                gate, _worker = self.controlled()
                if field == "dataset":
                    self.window.source_file = "different.pcap"
                else:
                    self.window.stream_controller.invalidate()
                gate.set()
                self.assertTrue(wait_until(lambda: self.window.stream_thread is None))
                self.assertIsNone(self.window.stream_result)
                self.assertIn("过期", self.window.notice)

    def test_clear_and_newly_appended_data_invalidate_stream_results(self):
        self.analyze()
        self.offer(dns_packets())
        self.assertIsNone(self.window.stream_result)
        self.assertIsNone(self.window.stream_controller.result)
        self.analyze(offer=False)
        self.window.clear_packets()
        self.assertIsNone(self.window.stream_result)
        self.assertEqual(self.window.source_model.columnCount(), 8)
        self.assertIn("尚未分析", self.window.stream_status_label.text())

    def test_new_capture_invalidates_results_without_npcap(self):
        self.analyze()
        self.window._capture_interface = "fake0"
        factory = SnifferFactory()
        with patch.object(main, "CaptureWorker", lambda device, buffer: CaptureWorker(device, buffer, factory)):
            self.window.start_capture()
        self.assertIsNone(self.window.stream_result)
        self.assertIn("尚未分析", self.window.stream_status_label.text())
        self.assertTrue(wait_until(lambda: factory.instances and factory.instances[0].ready.is_set()))
        self.window.stop_capture()
        self.assertTrue(wait_until(lambda: self.window.capture_thread is None))

    def test_successful_import_invalidates_stream_results(self):
        self.analyze()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.pcap"
            wrpcap(str(path), dns_packets())
            self.window.open_path(str(path))
            self.assertTrue(wait_until(lambda: self.window.load_thread is None))
        self.assertIsNone(self.window.stream_result)
        self.assertEqual(self.window.source_model.columnCount(), 8)
        self.assertIn("尚未分析", self.window.stream_status_label.text())

    def test_failed_and_cancelled_import_preserve_result_and_filter(self):
        old = self.analyze()
        label = self.window.stream_status_label.text()
        self.window.port_edit.setText("51002")
        self.window.apply_display_filter()
        count = self.window.displayed_packets
        with tempfile.TemporaryDirectory() as directory:
            self.window.open_path(str(Path(directory) / "missing.pcap"))
            self.assertTrue(wait_until(lambda: self.window.load_thread is None))
        self.assert_result_preserved(old, label)
        self.assertEqual(self.window.displayed_packets, count)
        with patch.object(main, "LoadWorker", ControlledLoadWorker):
            self.window.open_path("cancel.pcap")
            self.window.stop_capture()
            self.assertTrue(wait_until(lambda: self.window.load_thread is None))
        self.assert_result_preserved(old, label)
        self.assertEqual(self.window.displayed_packets, count)

    def test_filtered_save_keeps_all_original_packet_bytes(self):
        self.offer()
        before = [bytes(packet) for packet in self.window.packets]
        self.analyze(offer=False)
        self.window.port_edit.setText("51002")
        self.window.apply_display_filter()
        self.assertLess(self.window.displayed_packets, 31)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.pcap"
            self.window.save_to_path(str(path))
            self.assertTrue(wait_until(lambda: self.window.save_thread is None))
            restored = rdpcap(str(path))
        self.assertEqual([bytes(packet) for packet in restored], before)
        self.assertEqual([bytes(packet) for packet in self.window.packets], before)

    def test_close_requests_cancel_and_does_not_commit_late_result(self):
        self.offer()
        self.window.show()
        gate, worker = self.controlled()
        self.window.close()
        self.assertTrue(self.window._closing)
        self.assertTrue(worker.cancel_event.is_set())
        self.assertIs(self.window.stream_thread, worker)
        gate.set()
        self.assertTrue(wait_until(lambda: self.window.stream_thread is None))
        self.assertIsNone(self.window.stream_result)
        self.assertFalse(self.window.isVisible())


if __name__ == "__main__":
    unittest.main()
