"""第三阶段 GUI 的筛选、PCAP 文件模式及生命周期集成测试。"""

import struct
import tempfile
import unittest
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

from helpers import SnifferFactory, app, wait_until
from PySide6.QtCore import QThread
from PySide6.QtTest import QTest
from scapy.all import Ether, IP, Raw, TCP, UDP

import main


def packet(src="192.0.2.1", dst="192.0.2.2", sport=1234, dport=80, payload=b"test"):
    """构造带显式 MAC 和原始字节的 Ethernet/TCP 测试包。"""
    frame = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport)
        / Raw(payload)
    )
    result = Ether(bytes(frame))
    result.time = 1700000000.125
    return result


def udp_packet(index=0):
    """构造不同地址的 UDP 包，便于验证文件导入顺序。"""
    frame = (
        Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:04")
        / IP(src=f"198.51.100.{(index % 250) + 1}", dst="203.0.113.1")
        / UDP(sport=10000 + index % 50000, dport=53)
        / Raw(f"packet-{index}".encode())
    )
    result = Ether(bytes(frame))
    result.time = 1700000000.125
    return result


def pcap_bytes(packets):
    """构造经典 little-endian PCAP，避免依赖被测保存流程。"""
    records = [bytes(value) for value in packets]
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, raw in enumerate(records):
        data.extend(struct.pack("<IIII", 1700000000 + index, 125000, len(raw), len(raw)))
        data.extend(raw)
    return bytes(data)


class Stage3GuiTests(unittest.TestCase):
    """在 offscreen Qt 中验证第三阶段窗口的跨组件行为。"""

    @classmethod
    def setUpClass(cls):
        cls.application = app()

    def setUp(self):
        interfaces = [
            SimpleNamespace(network_name="fake0", name="测试网卡一", ip="192.0.2.1"),
            SimpleNamespace(network_name="fake1", name="测试网卡二", ip="192.0.2.2"),
        ]
        self.patchers = [
            patch.object(main, "get_interfaces", return_value=interfaces),
            patch.object(main, "conf", SimpleNamespace(iface="fake1", loopback_name="fake0")),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.window = main.SnifferWindow()

    def tearDown(self):
        if self.window.load_thread is not None:
            self.window.stop_capture()
        if self.window.capture_thread is not None:
            self.window.stop_capture()
        self.assertTrue(
            wait_until(
                lambda: not self.window.is_busy()
                and self.window.buffer.snapshot().pending == 0,
                timeout=8,
            )
        )
        self.window.close()
        self.window.deleteLater()
        QTest.qWait(20)

    def offer(self, packets):
        """将包放入应用缓存并完成一次显示排空。"""
        for value in packets:
            self.window.buffer.offer(value)
        self.window.flush_pending_packets()

    def write_pcap(self, directory, packets, name="input.pcap"):
        path = Path(directory) / name
        path.write_bytes(pcap_bytes(packets))
        return path

    def open_and_wait(self, path, timeout=10):
        """启动异步导入并等待窗口回收读取线程。"""
        self.window.open_path(str(path))
        self.assertTrue(wait_until(lambda: self.window.load_thread is None, timeout=timeout))

    def capture(self, factory):
        """注入内存抓包生产者，避免触碰真实网卡。"""
        from capture_engine import CaptureWorker

        with patch.object(
            main,
            "CaptureWorker",
            lambda interface, buffer: CaptureWorker(interface, buffer, factory),
        ):
            self.window.start_capture()

    def test_filtered_source_row_drives_matching_detail(self):
        """筛选后的第一行仍展示原始第二行的详情与原始字节。"""
        samples = [
            packet(dport=80, payload=b"first"),
            packet(src="192.0.2.9", dst="192.0.2.10", dport=443, payload=b"selected"),
            packet(dport=22, payload=b"third"),
        ]
        self.offer(samples)
        self.window.protocol_box.setCurrentText("TCP")
        self.window.port_edit.setText("443")
        self.assertTrue(self.window.apply_display_filter())
        self.assertEqual(self.window.displayed_packets, 1)
        self.assertEqual(self.window.proxy_model.mapToSource(self.window.proxy_model.index(0, 0)).row(), 1)

        self.window.packet_table.selectRow(0)
        QTest.qWait(20)
        details = self.window.detail_text.toPlainText()
        self.assertIn("192.0.2.9", details)
        self.assertIn(samples[1].original.hex(" "), details)
        self.assertNotIn("src       = 192.0.2.1\n", details)

    def test_invalid_filter_keeps_previous_valid_condition(self):
        """非法筛选只更新提示，不覆盖上一组有效条件。"""
        self.offer([packet(dport=80), packet(dport=443)])
        self.window.protocol_box.setCurrentText("TCP")
        self.assertTrue(self.window.apply_display_filter())
        previous = self.window.filter_spec
        self.assertEqual(self.window.displayed_packets, 2)

        self.window.ip_edit.setText("not-an-ip")
        self.assertFalse(self.window.apply_display_filter())
        self.assertEqual(self.window.filter_spec, previous)
        self.assertEqual(self.window.proxy_model.spec, previous)
        self.assertEqual(self.window.displayed_packets, 2)
        self.assertIn("上一组有效条件", self.window.filter_status.text())

    def test_successful_classic_pcap_replaces_data_and_enters_file_mode(self):
        """成功读取经典 PCAP 会替换旧数据并锁定文件模式。"""
        old = packet(src="192.0.2.50", dst="192.0.2.51", payload=b"old")
        incoming = [udp_packet(1), udp_packet(2)]
        self.offer([old])
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pcap(directory, incoming, "替换.pcap")
            self.open_and_wait(path)
            self.assertEqual([bytes(value) for value in self.window.packets], [bytes(value) for value in incoming])
            self.assertEqual(self.window.source_file, str(path))
            self.assertEqual(self.window.state, "stopped")
            self.assertIn("文件模式：替换.pcap", self.window.status_label.text())
            self.assertFalse(self.window.start_button.isEnabled())
            self.window.start_capture()
            self.assertIn("文件模式", self.window.notice)

    def test_import_more_than_2048_packets_is_not_truncated(self):
        """文件模式导入 2500 个包时保留完整记录和表格行。"""
        self.window.limit_box.setValue(3000)
        packets = [udp_packet(index) for index in range(2500)]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pcap(directory, packets, "large.pcap")
            self.open_and_wait(path, timeout=15)
            self.assertEqual(len(self.window.packets), 2500)
            self.assertEqual(self.window.packet_model.rowCount(), 2500)
            self.assertEqual(self.window.proxy_model.rowCount(), 2500)
            self.assertEqual(self.window.buffer.snapshot().accepted, 2500)
            self.assertFalse(self.window.buffer.snapshot().limit_reached)

    def test_load_failure_keeps_existing_model_and_data(self):
        """读取失败会恢复替换前的模型、缓存和实时模式。"""
        samples = [packet(payload=b"keep-1"), packet(dport=443, payload=b"keep-2")]
        self.offer(samples)
        before_model = self.window.packet_model
        before_buffer = self.window.buffer
        before_bytes = [bytes(value) for value in self.window.packets]
        with tempfile.TemporaryDirectory() as directory:
            self.window.open_path(str(Path(directory) / "missing.pcap"))
            self.assertTrue(wait_until(lambda: self.window.load_thread is None, timeout=8))
        self.assertIs(self.window.packet_model, before_model)
        self.assertIs(self.window.buffer, before_buffer)
        self.assertEqual([bytes(value) for value in self.window.packets], before_bytes)
        self.assertEqual(self.window.source_file, "")
        self.assertEqual(self.window.state, "error")
        self.assertIn("读取失败", self.window.notice)

    def test_load_cancel_keeps_existing_model_and_data(self):
        """取消读取不会发布半成品，也不会丢弃替换前的数据。"""
        samples = [packet(payload=b"before-cancel")]
        self.offer(samples)
        before_model = self.window.packet_model
        before_buffer = self.window.buffer
        before_bytes = [bytes(value) for value in self.window.packets]
        cancelled = Event()

        class BlockingLoadWorker(QThread):
            """等待取消信号的读取替身，覆盖窗口取消收尾逻辑。"""

            def __init__(self, path, max_packets, max_bytes):
                super().__init__()
                self.path = path
                self.max_packets = max_packets
                self.max_bytes = max_bytes
                self.error = ""
                self.packets = []
                self.cancelled = False

            def request_cancel(self):
                self.cancelled = True
                cancelled.set()

            def run(self):
                cancelled.wait(5)

        with patch.object(main, "LoadWorker", BlockingLoadWorker):
            self.window.open_path("cancelled.pcap")
            self.assertTrue(wait_until(lambda: self.window.load_thread is not None))
            self.window.stop_capture()
            self.assertTrue(wait_until(lambda: self.window.load_thread is None, timeout=8))

        self.assertIs(self.window.packet_model, before_model)
        self.assertIs(self.window.buffer, before_buffer)
        self.assertEqual([bytes(value) for value in self.window.packets], before_bytes)
        self.assertEqual(self.window.source_file, "")
        self.assertEqual(self.window.state, "stopped")
        self.assertIn("读取已取消", self.window.notice)

    def test_clear_file_mode_restores_realtime_capture(self):
        """清空文件模式后恢复网卡控件并可重新开始实时抓包。"""
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pcap(directory, [udp_packet(1)], "one.pcap")
            self.open_and_wait(path)
        self.assertTrue(self.window.source_file)
        self.window.clear_packets()
        self.assertEqual(self.window.source_file, "")
        self.assertEqual(self.window.windowTitle(), "实验 1A · 网络嗅探器 · 第三阶段")
        self.assertEqual(self.window.packet_model.rowCount(), 0)
        self.assertEqual(self.window.buffer.snapshot().received, 0)
        self.assertTrue(self.window.start_button.isEnabled())
        self.assertTrue(self.window.interface_box.isEnabled())
        self.assertEqual(self.window.filter_spec.protocol, "全部")

        factory = SnifferFactory(packets=[packet(payload=b"live")])
        self.capture(factory)
        self.assertTrue(wait_until(lambda: self.window.buffer.snapshot().received == 1))
        self.window.stop_capture()
        self.assertTrue(wait_until(lambda: self.window.capture_thread is None, timeout=8))
        self.assertEqual(len(self.window.packets), 1)
        self.assertEqual(self.window.source_file, "")


if __name__ == "__main__":
    unittest.main()
