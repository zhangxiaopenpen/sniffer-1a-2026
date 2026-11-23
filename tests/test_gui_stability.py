"""无真实网卡的模型、GUI 生命周期和万行响应回归测试。"""

import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from helpers import SnifferFactory, app, wait_until
from PySide6.QtCore import QModelIndex, QThread, QTimer, Qt
from PySide6.QtTest import QSignalSpy, QTest
from scapy.all import ARP, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, rdpcap
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6ExtHdrHopByHop
from scapy.layers.vxlan import VXLAN

import main
import packet_model
from capture_engine import CaptureWorker, PacketBuffer
from packet_model import PacketTableModel


def packet(network=None):
    """构造带显式 MAC 的已解析样本，避免序列化时查询真实网络。"""
    if network is None:
        network = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=1234, dport=80) / Raw(b"test" * 20)
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / network
    result = Ether(bytes(frame))
    result.time = 1700000000.125
    return result


class TimedSave(QThread):
    """可确定退出时机的保存替身，不生成文件。"""

    failure = ""

    def __init__(self, path, packets):
        """保留 SaveWorker 的公开结果字段。"""
        super().__init__()
        self.path, self.packets = path, tuple(packets)
        self.error = ""
        self.completed = False

    def run(self):
        """延迟结束，用于观察 GUI 在等待期间是否仍处理事件。"""
        self.msleep(250)
        self.error = self.failure
        self.completed = True


class ModelTests(unittest.TestCase):
    """验证公开表格行为、协议分类和按需解析。"""

    @classmethod
    def setUpClass(cls):
        """创建共享 Qt 应用。"""
        cls.application = app()

    def test_protocol_address_port_and_length_columns(self):
        """不同协议保留各自地址、端口与捕获长度。"""
        ipv4 = lambda: IP(src="192.0.2.1", dst="192.0.2.2")
        ipv6 = lambda: IPv6(src="2001:db8::1", dst="2001:db8::2")
        cases = [
            (ipv4() / TCP(sport=1234, dport=80), "TCP", "192.0.2.1", "192.0.2.2", "1234", "80"),
            (ipv4() / UDP(sport=5353, dport=53), "UDP", "192.0.2.1", "192.0.2.2", "5353", "53"),
            (ipv4() / ICMP(), "ICMP", "192.0.2.1", "192.0.2.2", "-", "-"),
            (ipv4(), "IPv4", "192.0.2.1", "192.0.2.2", "-", "-"),
            (ipv6() / TCP(sport=3210, dport=443), "TCP", "2001:db8::1", "2001:db8::2", "3210", "443"),
            (ipv6() / UDP(sport=53, dport=5353), "UDP", "2001:db8::1", "2001:db8::2", "53", "5353"),
            (ipv6() / ICMPv6EchoRequest(), "ICMPv6", "2001:db8::1", "2001:db8::2", "-", "-"),
            (ipv6(), "IPv6", "2001:db8::1", "2001:db8::2", "-", "-"),
            (ARP(psrc="192.0.2.3", pdst="192.0.2.4", hwsrc="02:00:00:00:00:01",
                 hwdst="00:00:00:00:00:00"), "ARP", "192.0.2.3", "192.0.2.4", "-", "-"),
            (Raw(b"other"), "other", "02:00:00:00:00:01", "02:00:00:00:00:02", "-", "-"),
        ]
        model = PacketTableModel()
        samples = [packet(case[0]) for case in cases]
        model.append_batch(samples)
        self.assertEqual(model.columnCount(), 8)
        self.assertEqual(model.rowCount(), len(samples))
        for row, (_, protocol, src, dst, sport, dport) in enumerate(cases):
            with self.subTest(protocol=protocol, source=src):
                values = [model.data(model.index(row, column)) for column in range(8)]
                self.assertEqual(values[0], str(row + 1))
                self.assertRegex(values[1], r"^\d{2}:\d{2}:\d{2}\.125$")
                self.assertEqual(values[2:], [src, dst, protocol, sport, dport, str(len(samples[row].original))])
                self.assertIs(model.packets[row], samples[row])

    def test_outer_network_addresses_protocol_and_ports_stay_consistent(self):
        """隧道包仅展示外层字段，IPv6 扩展头后的直属 TCP 仍可识别。"""
        inner = (Ether(src="02:00:00:00:01:01", dst="02:00:00:00:01:02")
                 / IP(src="203.0.113.1", dst="203.0.113.2") / TCP(sport=1234, dport=443))
        cases = [
            (IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=50000, dport=4789)
             / VXLAN(vni=42) / inner,
             ["192.0.2.1", "192.0.2.2", "UDP", "50000", "4789"]),
            (IPv6(src="2001:db8::1", dst="2001:db8::2")
             / IP(src="203.0.113.1", dst="203.0.113.2") / TCP(sport=1234, dport=443),
             ["2001:db8::1", "2001:db8::2", "IPv6", "-", "-"]),
            (IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop()
             / TCP(sport=3210, dport=443),
             ["2001:db8::1", "2001:db8::2", "TCP", "3210", "443"]),
        ]
        model = PacketTableModel()
        model.append_batch([packet(network) for network, _ in cases])
        for row, (_, expected) in enumerate(cases):
            with self.subTest(protocol=expected[2]):
                self.assertEqual([model.data(model.index(row, column)) for column in range(2, 7)], expected)

    def test_original_length_and_lazy_cache_reset(self):
        """插入不解析，显示缓存直到清空，原始长度不受后续字段修改影响。"""
        model = PacketTableModel()
        sample = packet()
        original_length = len(sample.original)
        sample[Raw].load += b"changed after capture"
        self.assertNotEqual(len(sample), original_length)
        reset = QSignalSpy(model.modelReset)
        with patch.object(packet_model, "packet_addresses", wraps=packet_model.packet_addresses) as parse:
            model.append_batch([sample, packet()])
            parse.assert_not_called()
            self.assertEqual(model.data(model.index(0, 7)), str(original_length))
            for column in range(8):
                model.data(model.index(0, column))
            self.assertEqual(parse.call_count, 1)
            model.clear()
            self.assertEqual(reset.count(), 1)
            self.assertEqual(model.rowCount(), 0)
            replacement = packet(IP(src="192.0.2.9", dst="192.0.2.10") / UDP(sport=9, dport=10))
            model.append_batch([replacement])
            self.assertEqual(model.data(model.index(0, 2)), "192.0.2.9")
            self.assertEqual(model.data(model.index(0, 0)), "1")
            self.assertEqual(parse.call_count, 2)

    def test_invalid_indices_roles_and_empty_batches(self):
        """空批次不发插入信号，无效索引及非显示角色不解析数据。"""
        model = PacketTableModel()
        inserted = QSignalSpy(model.rowsInserted)
        model.append_batch([])
        self.assertEqual(inserted.count(), 0)
        model.append_batch([packet()])
        other = PacketTableModel()
        other.append_batch([packet()])
        self.assertIsNone(model.data(QModelIndex()))
        self.assertIsNone(model.data(other.index(0, 0)))
        self.assertIsNone(model.data(model.index(0, 0), Qt.ItemDataRole.UserRole))
        self.assertIsNone(model.headerData(8, Qt.Orientation.Horizontal))
        self.assertEqual(model.rowCount(model.index(0, 0)), 0)
        self.assertEqual(model.columnCount(model.index(0, 0)), 0)


class GuiTests(unittest.TestCase):
    """通过真实后台替身线程验证窗口状态和数据一致性。"""

    @classmethod
    def setUpClass(cls):
        """创建共享 Qt 应用。"""
        cls.application = app()

    def setUp(self):
        """替换所有接口枚举和默认接口来源，避免真实网卡依赖。"""
        interfaces = [SimpleNamespace(network_name="fake0", name="测试网卡一", ip="192.0.2.1"),
                      SimpleNamespace(network_name="fake1", name="测试网卡二", ip="192.0.2.2")]
        self.patchers = [patch.object(main, "get_interfaces", return_value=interfaces),
                         patch.object(main, "conf", SimpleNamespace(iface="fake1", loopback_name="fake0"))]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.window = main.SnifferWindow()

    def tearDown(self):
        """退出全部后台线程后销毁窗口，避免测试间遗留 Qt 对象。"""
        if self.window.capture_thread is not None:
            self.window.stop_capture()
        if self.window.is_busy() or self.window.buffer.snapshot().pending:
            self.window.packet_timer.start(10)
        self.assertTrue(wait_until(lambda: not self.window.is_busy() and self.window.buffer.snapshot().pending == 0))
        self.window.close()
        self.window.deleteLater()
        QTest.qWait(20)

    def capture(self, factory):
        """以注入的内存生产者启动真实 CaptureWorker。"""
        with patch.object(main, "CaptureWorker", lambda interface, buffer: CaptureWorker(interface, buffer, factory)):
            self.window.start_capture()

    def stopped(self):
        """在后台退出并完成排空后返回真。"""
        return self.window.capture_thread is None and self.window.buffer.snapshot().pending == 0

    def offer(self, samples):
        """直接注入少量已捕获样本供纯展示及保存测试使用。"""
        for sample in samples:
            self.window.buffer.offer(sample)
        self.window.flush_pending_packets()

    def test_defaults_and_default_interface_selection(self):
        """默认接口无需手动选择，保留设置和刷新频率满足约定。"""
        self.assertEqual(self.window.interface_box.currentData(), "fake1")
        self.assertEqual(self.window.limit_box.value(), 1000)
        self.assertEqual((self.window.limit_box.minimum(), self.window.limit_box.maximum()), (10, 10000))
        self.assertEqual(self.window.buffer.max_packets, 1000)
        self.assertEqual(self.window.packet_timer.interval(), 100)
        self.assertIs(self.window.packet_table.model(), self.window.packet_model)
        self.assertTrue(self.window.start_button.isEnabled())

    def test_empty_and_failed_interface_enumeration_disable_capture(self):
        """无网卡与枚举错误都显示错误状态且不能启动线程。"""
        for failure in (False, True):
            with self.subTest(failure=failure), patch.object(main, "get_interfaces", return_value=[],
                                                          side_effect=OSError("enumeration failed") if failure else None):
                self.window.load_interfaces()
                self.assertEqual(self.window.state, "error")
                self.assertFalse(self.window.start_button.isEnabled())
                with patch.object(main, "CaptureWorker") as worker:
                    self.window.start_capture()
                    worker.assert_not_called()

    def test_single_flush_displays_at_most_250_packets(self):
        """一次刷新只消费限定批次，其余包保持原有顺序。"""
        self.window.packet_timer.stop()
        samples = [packet()] * 600
        self.offer(samples)
        self.assertEqual(self.window.packet_model.rowCount(), 250)
        self.assertEqual(self.window.buffer.snapshot().pending, 350)
        self.window.flush_pending_packets()
        self.assertEqual(self.window.packet_model.rowCount(), 500)
        self.assertEqual(self.window.buffer.snapshot().pending, 100)

    def test_stop_drains_freezes_count_and_saved_count_matches(self):
        """停止后排空、冻结计数，并把完整保留集保存到 pcap。"""
        self.window.limit_box.setValue(2000)
        self.capture(SnifferFactory(packets=[packet()] * 1200))
        self.assertTrue(wait_until(lambda: self.window.buffer.snapshot().received == 1200))
        self.assertFalse(self.window.clear_button.isEnabled())
        self.assertFalse(self.window.save_button.isEnabled())
        self.window.stop_capture()
        self.assertTrue(wait_until(self.stopped))
        stats = self.window.buffer.snapshot()
        self.assertEqual((stats.accepted, stats.pending), (1200, 0))
        self.assertEqual(stats.received, stats.accepted + stats.dropped)
        self.assertEqual(self.window.packet_model.rowCount(), stats.accepted)
        QTest.qWait(300)
        self.assertEqual(self.window.buffer.snapshot(), stats)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "完整数据.pcap"
            self.window.save_to_path(str(path))
            self.assertTrue(wait_until(lambda: self.window.save_thread is None))
            self.assertEqual(len(rdpcap(str(path))), stats.accepted)

    def test_repeated_start_stop_resume_and_clear(self):
        """快速启停可恢复，停止后继续累计，清空恢复设置控件。"""
        for _ in range(3):
            self.capture(SnifferFactory(delay=0.02))
            self.window.stop_capture()
            self.assertTrue(wait_until(self.stopped))
            self.assertTrue(self.window.start_button.isEnabled())
        original = self.window.buffer
        for total in (10, 20):
            self.capture(SnifferFactory(packets=[packet()] * 10))
            self.assertTrue(wait_until(lambda: self.window.buffer.snapshot().received == total))
            self.window.stop_capture()
            self.assertTrue(wait_until(self.stopped))
            self.assertEqual(len(self.window.packets), total)
            self.assertIs(self.window.buffer, original)
            self.assertFalse(self.window.interface_box.isEnabled())
            self.assertFalse(self.window.limit_box.isEnabled())
        self.window.limit_box.setValue(500)
        self.assertEqual(self.window.limit_box.value(), 1000)
        self.window.clear_packets()
        self.assertEqual(self.window.packet_model.rowCount(), 0)
        self.assertEqual(self.window.buffer.snapshot().received, 0)
        self.assertEqual(self.window.buffer.snapshot().dropped, 0)
        self.assertTrue(self.window.interface_box.isEnabled())
        self.assertTrue(self.window.limit_box.isEnabled())

    def test_retention_limit_stops_and_requires_clear(self):
        """达到保留上限后自动停止，清空之前不能重新抓包。"""
        self.window.limit_box.setValue(10)
        self.capture(SnifferFactory(packets=[packet()] * 100))
        self.assertTrue(wait_until(self.stopped))
        self.assertEqual(len(self.window.packets), 10)
        self.assertTrue(self.window.buffer.snapshot().limit_reached)
        self.assertFalse(self.window.start_button.isEnabled())
        self.assertTrue(self.window.clear_button.isEnabled())
        self.window.clear_packets()
        self.assertTrue(self.window.start_button.isEnabled())
        self.assertEqual(self.window.buffer.max_packets, 10)

    def test_save_failure_keeps_original_file_packets_and_allows_retry(self):
        """原子替换失败时保留旧文件和内存数据，恢复保存按钮。"""
        samples = [packet()] * 12
        self.offer(samples)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(b"old data")
            with patch("capture_engine.os.replace", side_effect=OSError("disk full")):
                self.window.save_to_path(str(path))
                self.assertFalse(self.window.start_button.isEnabled())
                self.assertFalse(self.window.clear_button.isEnabled())
                self.assertTrue(wait_until(lambda: self.window.save_thread is None))
            self.assertEqual(path.read_bytes(), b"old data")
            self.assertEqual(self.window.packets, samples)
            self.assertEqual(self.window.state, "error")
            self.assertTrue(self.window.save_button.isEnabled())
            self.window.save_to_path(str(path))
            self.assertTrue(wait_until(lambda: self.window.save_thread is None))
            self.assertEqual(len(rdpcap(str(path))), 12)

    def test_save_uses_confirmed_dotfile_path_without_touching_suffixed_neighbor(self):
        """已确认的隐藏文件路径原样保存，不覆写未经确认的相邻 pcap。"""
        sample = packet()
        self.offer([sample])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / ".capture"
            neighbor = Path(directory) / ".capture.pcap"
            neighbor.write_bytes(b"unconfirmed neighboring file")
            self.window.save_to_path(str(target))
            self.assertTrue(wait_until(lambda: self.window.save_thread is None))
            self.assertEqual(self.window.state, "stopped")
            self.assertTrue(target.is_file())
            saved = rdpcap(str(target))
            self.assertEqual(len(saved), 1)
            self.assertEqual(bytes(saved[0]), sample.original)
            self.assertEqual(neighbor.read_bytes(), b"unconfirmed neighboring file")

    def test_startup_failure_recovers_controls(self):
        """打开接口失败后不遗留忙状态，允许用户重试。"""
        self.capture(SnifferFactory(failure="invalid interface"))
        self.assertTrue(wait_until(self.stopped))
        self.assertEqual(self.window.state, "error")
        self.assertIn("invalid interface", self.window.notice)
        self.assertTrue(self.window.start_button.isEnabled())
        self.assertTrue(self.window.interface_box.isEnabled())

    def test_close_waits_for_capture_without_blocking_gui(self):
        """关闭先等待生产者退出，期间 Qt 心跳保持运行。"""
        factory = SnifferFactory(stop_delay=0.25)
        self.window.show()
        self.capture(factory)
        self.assertTrue(wait_until(lambda: factory.instances and factory.instances[0].ready.is_set()))
        ticks = []
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(time.monotonic()))
        timer.start(10)
        try:
            started = time.monotonic()
            self.window.close()
            self.assertLess(time.monotonic() - started, 0.20)
            self.assertTrue(self.window.isVisible())
            self.assertTrue(wait_until(lambda: not self.window.isVisible()))
            self.assertGreaterEqual(len(ticks), 5)
            self.assertFalse(factory.instances[0].thread.is_alive())
        finally:
            timer.stop()

    def test_close_waits_for_background_save_and_failure_preserves_window(self):
        """保存完成后关闭；失败则取消关闭并保留可重试的数据。"""
        self.offer([packet()])
        self.window.show()
        for failure in ("save failed", ""):
            with self.subTest(failure=failure), patch.object(main, "SaveWorker", TimedSave), patch.object(TimedSave, "failure", failure):
                self.window.save_to_path("unused.pcap")
                worker = self.window.save_thread
                started = time.monotonic()
                self.window.close()
                self.assertLess(time.monotonic() - started, 0.20)
                self.assertTrue(self.window.isVisible())
                self.assertTrue(wait_until(lambda: self.window.save_thread is None))
                self.assertTrue(worker.completed)
                self.assertEqual(self.window.isVisible(), bool(failure))
                if failure:
                    self.assertEqual(len(self.window.packets), 1)
                    self.assertEqual(self.window.state, "error")
                    self.assertFalse(self.window._closing)
                    self.assertTrue(self.window.save_button.isEnabled())

    def test_selection_details_and_hex_preserve_original_bytes(self):
        """选择对应原始顺序，详情中的十六进制不重建已经修改的包。"""
        selected = packet(IP(src="192.0.2.99", dst="192.0.2.100") / TCP(sport=99, dport=443) / Raw(b"selected"))
        original = selected.original
        selected[IP].ttl = 7
        self.assertNotEqual(bytes(selected), original)
        self.offer([packet(), selected])
        self.window.packet_table.selectRow(1)
        details = self.window.detail_text.toPlainText()
        self.assertIn("192.0.2.99", details)
        self.assertIn(selected.show(dump=True), details)
        self.assertEqual(details.split("十六进制原始数据：\n", 1)[1], original.hex(" "))
        self.window.packet_table.clearSelection()
        self.assertEqual(self.window.detail_text.toPlainText(), "")

    def test_10000_rows_batch_drain_keeps_qt_heartbeat_and_last_row_details(self):
        """万行消费期间持续响应事件，末行仍能正确选择和查看。"""
        self.window.buffer = PacketBuffer(max_packets=10000, max_pending=10000)
        sample = packet()
        last = packet(IP(src="192.0.2.254", dst="192.0.2.253") / TCP(sport=65530, dport=443))
        for value in [sample] * 9999 + [last]:
            self.window.buffer.offer(value)
        self.window.show()
        ticks = [time.monotonic()]
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(time.monotonic()))
        timer.start(10)
        started = time.monotonic()
        try:
            self.assertTrue(wait_until(lambda: self.window.buffer.snapshot().pending == 0, timeout=8))
        finally:
            timer.stop()
        elapsed = time.monotonic() - started
        max_gap = max((later - earlier for earlier, later in zip(ticks, ticks[1:])), default=elapsed)
        print(f"\nGUI pressure: rows=10000, elapsed={elapsed:.3f}s, heartbeat_count={len(ticks)}, max_gap={max_gap:.3f}s")
        self.assertEqual(self.window.packet_model.rowCount(), 10000)
        self.assertGreater(len(ticks), 50)
        self.assertLess(max_gap, 1.0)
        self.window.packet_table.selectRow(9999)
        self.assertIn("192.0.2.254", self.window.detail_text.toPlainText())
        self.assertTrue(self.window.detail_text.toPlainText().endswith(last.original.hex(" ")))


if __name__ == "__main__":
    unittest.main()
