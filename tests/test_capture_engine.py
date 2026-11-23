"""有界缓存、无网络线程生命周期及原子 PCAP 保存回归测试。"""

import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from scapy.all import Ether, IP, Loopback, Raw, TCP, conf, rdpcap
from scapy.utils import RawPcapReader

from capture_engine import CaptureWorker, PacketBuffer, SaveWorker
from helpers import SnifferFactory, app, wait_until


def ethernet_packet(payload=b"payload"):
    """构造使用文档地址和显式 MAC 的离线 Ethernet 数据包。"""
    return (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / TCP(sport=12345, dport=80)
        / Raw(payload)
    )


class BufferTests(unittest.TestCase):
    """验证容量边界、顺序及并发计数守恒。"""

    def test_nonpositive_budgets_are_rejected(self):
        """所有数量和字节上限都必须为正数。"""
        for name in ("max_packets", "max_bytes", "max_pending", "max_pending_bytes"):
            for value in (0, -1):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    PacketBuffer(**{name: value})

    def test_queue_overload_is_bounded_counted_and_recovers(self):
        """待消费包数过载只丢队列包，排空后能够继续接收。"""
        buffer = PacketBuffer(max_packets=20000, max_pending=16)
        for _ in range(10000):
            self.assertIsNone(buffer.offer(b"x" * 64))
        stats = buffer.snapshot()
        self.assertEqual((stats.received, stats.accepted, stats.pending), (10000, 16, 16))
        self.assertEqual((stats.dropped, stats.drop_queue, stats.drop_limit), (9984, 9984, 0))
        self.assertFalse(stats.limit_reached)
        self.assertEqual(len(buffer.take_batch(8)), 8)
        buffer.offer(b"last")
        stats = buffer.snapshot()
        self.assertEqual((stats.accepted, stats.pending), (17, 9))
        self.assertEqual(stats.received, stats.accepted + stats.dropped)
        self.assertEqual(buffer.take_batch()[-1], b"last")

    def test_retained_count_is_not_released_by_consumption(self):
        """已消费包仍占用本轮总包数预算。"""
        buffer = PacketBuffer(max_packets=3, max_pending=3)
        buffer.offer(b"a")
        buffer.offer(b"b")
        self.assertEqual(buffer.take_batch(), [b"a", b"b"])
        buffer.offer(b"c")
        buffer.offer(b"d")
        stats = buffer.snapshot()
        self.assertEqual((stats.accepted, stats.pending, stats.drop_limit), (3, 1, 1))
        self.assertTrue(stats.limit_reached)
        self.assertEqual(buffer.take_batch(), [b"c"])

    def test_retained_bytes_are_not_released_by_consumption(self):
        """消费队列不会重新获得总字节预算。"""
        buffer = PacketBuffer(max_bytes=10)
        buffer.offer(b"123456")
        self.assertEqual(buffer.take_batch(), [b"123456"])
        buffer.offer(b"7890")
        buffer.offer(b"x")
        stats = buffer.snapshot()
        self.assertEqual((stats.accepted, stats.retained_bytes, stats.drop_limit), (2, 10, 1))
        self.assertTrue(stats.limit_reached)

    def test_retained_byte_budget_exact_and_oversize(self):
        """恰好达到或单包超出总预算均会锁定自动停止状态。"""
        for size, accepted in ((10, 1), (11, 0)):
            with self.subTest(size=size):
                buffer = PacketBuffer(max_bytes=10)
                buffer.offer(b"x" * size)
                buffer.offer(b"a")
                stats = buffer.snapshot()
                self.assertEqual(stats.accepted, accepted)
                self.assertTrue(stats.limit_reached)
                self.assertLessEqual(stats.retained_bytes, 10)
                self.assertEqual(stats.drop_limit, 2 - accepted)
                self.assertEqual(stats.received, stats.accepted + stats.dropped)

    def test_original_capture_size_controls_budgets(self):
        """修改解析字段后的重建长度不能取代原始捕获长度。"""
        raw = bytes(ethernet_packet(b"captured"))
        packet = Ether(raw)
        packet[Raw].load = b"edited" * 100
        self.assertGreater(len(packet), len(raw))
        buffer = PacketBuffer(max_bytes=len(raw), max_pending_bytes=len(raw))
        buffer.offer(packet)
        stats = buffer.snapshot()
        self.assertEqual((stats.accepted, stats.retained_bytes), (1, len(raw)))
        self.assertTrue(stats.limit_reached)

    def test_queue_byte_budget_recovers_after_drain(self):
        """队列字节预算独立统计，消费后释放。"""
        buffer = PacketBuffer(max_pending_bytes=10)
        buffer.offer(b"123456")
        buffer.offer(b"abcdef")
        self.assertEqual(buffer.snapshot().drop_queue, 1)
        self.assertFalse(buffer.snapshot().limit_reached)
        self.assertEqual(buffer.take_batch(), [b"123456"])
        buffer.offer(b"abcdef")
        stats = buffer.snapshot()
        self.assertEqual((stats.accepted, stats.pending, stats.retained_bytes), (2, 1, 12))

    def test_nonpositive_batch_size_does_not_consume(self):
        """空批次请求不会改变队列及总计数。"""
        buffer = PacketBuffer()
        buffer.offer(b"first")
        before = buffer.snapshot()
        for count in (0, -1):
            self.assertEqual(buffer.take_batch(count), [])
            self.assertEqual(buffer.snapshot(), before)
        self.assertEqual(buffer.take_batch(), [b"first"])

    def test_concurrent_producers_preserve_counts_and_per_producer_order(self):
        """并发接收没有丢失计数或打乱各生产者内部顺序。"""
        buffer = PacketBuffer(max_packets=5000, max_pending=5000)

        def produce(prefix):
            """提交一个生产者的有序包序列。"""
            for number in range(1000):
                buffer.offer(f"{prefix}:{number}".encode())

        threads = [Thread(target=produce, args=(index,)) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        packets = buffer.take_batch(5000)
        stats = buffer.snapshot()
        self.assertEqual((len(packets), stats.received, stats.accepted), (4000, 4000, 4000))
        self.assertEqual((stats.pending, stats.dropped), (0, 0))
        self.assertEqual(stats.retained_bytes, sum(map(len, packets)))
        for index in range(4):
            numbers = [int(p.split(b":")[1]) for p in packets if p.startswith(f"{index}:".encode())]
            self.assertEqual(numbers, list(range(1000)))

    def test_concurrent_overflow_preserves_total_budget(self):
        """并发超限仍严格满足 received = accepted + dropped。"""
        buffer = PacketBuffer(max_packets=513, max_pending=513)

        def produce():
            """并发灌入固定长度的离线数据。"""
            for _ in range(1000):
                buffer.offer(b"1234")

        threads = [Thread(target=produce) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        stats = buffer.snapshot()
        self.assertEqual((stats.received, stats.accepted, stats.dropped), (4000, 513, 3487))
        self.assertEqual((stats.pending, stats.retained_bytes), (513, 2052))
        self.assertEqual((stats.drop_queue, stats.drop_limit), (0, 3487))


class WorkerTests(unittest.TestCase):
    """验证启动、停止和生产者线程回收。"""

    @classmethod
    def setUpClass(cls):
        """创建整个测试类共用的 Qt 应用。"""
        cls.application = app()

    def start_worker(self, factory, buffer=None, stop_before=False):
        """启动可注入替身的 worker，并注册失败时的回收。"""
        worker = CaptureWorker("offline-test-interface", buffer or PacketBuffer(), factory)
        self.addCleanup(self.cleanup_worker, worker)
        if stop_before:
            worker.request_stop()
        worker.start()
        return worker

    @staticmethod
    def cleanup_worker(worker):
        """即使断言失败，也先停止线程再释放 Qt 对象。"""
        worker.request_stop()
        worker.wait(6500)

    def assert_finished(self, worker, factory):
        """完成状态必须意味着底层生产者也已真正退出。"""
        self.assertTrue(wait_until(worker.isFinished), "worker did not finish")
        self.assertTrue(worker.wait(100))
        for sniffer in factory.instances:
            self.assertFalse(sniffer.thread.is_alive())
            self.assertIs(sniffer.kwargs["promisc"], False)
            self.assertIs(sniffer.kwargs["store"], False)
            self.assertEqual(sniffer.kwargs["iface"], "offline-test-interface")
            self.assertEqual(sniffer.kwargs["prn"], worker.buffer.offer)
            self.assertTrue(callable(sniffer.kwargs["started_callback"]))

    def test_stop_before_start_does_not_open_device(self):
        """启动前的停止请求不会构造抓包器。"""
        factory = SnifferFactory()
        worker = self.start_worker(factory, stop_before=True)
        self.assert_finished(worker, factory)
        self.assertEqual(factory.instances, [])
        self.assertEqual((worker.error, worker.stop_reason), ("", "user"))

    def test_existing_limit_does_not_open_device(self):
        """已有数据达到预算时无需启动新的抓包线程。"""
        factory = SnifferFactory()
        buffer = PacketBuffer(max_packets=1)
        buffer.offer(b"full")
        worker = self.start_worker(factory, buffer)
        self.assert_finished(worker, factory)
        self.assertEqual(factory.instances, [])
        self.assertEqual((worker.error, worker.stop_reason), ("", "limit"))

    def test_stop_during_startup_waits_for_ready(self):
        """ready 前收到停止请求会等控制通道建立后再停止。"""
        factory = SnifferFactory(delay=0.2)
        worker = self.start_worker(factory)
        self.assertTrue(wait_until(lambda: bool(factory.instances)))
        self.assertFalse(factory.instances[0].ready.is_set())
        worker.request_stop()
        self.assert_finished(worker, factory)
        self.assertEqual((worker.error, worker.stop_reason), ("", "user"))
        self.assertEqual(factory.instances[0].stop_calls, 1)

    def test_idle_capture_stops_without_new_packet(self):
        """空闲抓包也能停止，并等待有延迟的底层退出。"""
        factory = SnifferFactory(stop_delay=0.15)
        worker = self.start_worker(factory)
        self.assertTrue(wait_until(lambda: factory.instances and factory.instances[0].ready.is_set()))
        worker.request_stop()
        self.assertTrue(wait_until(lambda: factory.instances[0].stop_event.is_set()))
        self.assertTrue(worker.isRunning())
        self.assert_finished(worker, factory)
        self.assertEqual((worker.error, worker.stop_reason), ("", "user"))
        self.assertEqual(worker.buffer.snapshot().received, 0)
        self.assertEqual(factory.instances[0].stop_calls, 1)

    def test_startup_error_is_reported_without_hanging(self):
        """底层启动错误传回调用方且不会遗留线程。"""
        factory = SnifferFactory(failure="driver unavailable")
        worker = self.start_worker(factory)
        self.assert_finished(worker, factory)
        self.assertIn("driver unavailable", worker.error)
        self.assertEqual(worker.stop_reason, "error")

    def test_unexpected_exit_is_reported(self):
        """未收到停止请求时的生产者退出属于错误。"""
        factory = SnifferFactory(end=True)
        worker = self.start_worker(factory)
        self.assert_finished(worker, factory)
        self.assertIn("意外结束", worker.error)
        self.assertEqual(worker.stop_reason, "error")

    def test_packet_retention_limit_automatically_stops_producer(self):
        """达到总包数上限后自动停止。"""
        factory = SnifferFactory(packets=[b"x"] * 1000)
        worker = self.start_worker(factory, PacketBuffer(max_packets=10, max_pending=10))
        self.assert_finished(worker, factory)
        stats = worker.buffer.snapshot()
        self.assertEqual((worker.error, worker.stop_reason), ("", "limit"))
        self.assertEqual(stats.accepted, 10)
        self.assertTrue(stats.limit_reached)
        self.assertEqual(stats.received, stats.accepted + stats.dropped)

    def test_byte_retention_limit_automatically_stops_producer(self):
        """达到总字节上限后也能自动停止。"""
        factory = SnifferFactory(packets=[b"12345"] * 100)
        worker = self.start_worker(factory, PacketBuffer(max_bytes=10))
        self.assert_finished(worker, factory)
        stats = worker.buffer.snapshot()
        self.assertEqual((worker.error, worker.stop_reason), ("", "limit"))
        self.assertEqual((stats.accepted, stats.retained_bytes), (2, 10))


class SaveTests(unittest.TestCase):
    """直接检查 PCAP 记录和失败后的文件系统状态。"""

    @classmethod
    def setUpClass(cls):
        """为后台保存线程创建 Qt 应用。"""
        cls.application = app()

    def save(self, path, packets):
        """运行保存线程并等待完全结束，返回最终结果。"""
        worker = SaveWorker(str(path), packets)
        worker.start()
        try:
            self.assertTrue(wait_until(worker.isFinished), "save did not finish")
        finally:
            self.assertTrue(worker.wait(3000))
        return worker

    def test_roundtrip_preserves_order_and_unicode_path(self):
        """中文路径可读回，包的字节及到达顺序保持不变。"""
        packets = [ethernet_packet(f"packet-{index}".encode()) for index in range(12)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "审核抓包.pcap"
            worker = self.save(path, packets)
            self.assertEqual(worker.error, "")
            self.assertEqual([bytes(p) for p in rdpcap(str(path))], [bytes(p) for p in packets])
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_original_bytes_take_priority_over_modified_fields(self):
        """解析后的字段被修改也必须导出最初捕获字节。"""
        originals = [bytes(ethernet_packet(f"original-{i}".encode())) for i in range(3)]
        packets = [Ether(raw) for raw in originals]
        for packet in packets:
            packet[IP].dst = "198.51.100.2"
            packet[Raw].load = b"modified payload with different length"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "originals.pcap"
            self.assertEqual(self.save(path, packets).error, "")
            with RawPcapReader(str(path)) as reader:
                self.assertEqual([raw for raw, _ in reader], originals)

    def test_nanosecond_timestamps_are_exact(self):
        """大秒值仍保留低位纳秒，不经过浮点舍入。"""
        times = [Decimal("1700000000.123456789"), Decimal("1700000001.000000001"), Decimal("0.999999999")]
        packets = [ethernet_packet() for _ in times]
        for packet, timestamp in zip(packets, times):
            packet.time = timestamp
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "times.pcap"
            self.assertEqual(self.save(path, packets).error, "")
            with RawPcapReader(str(path)) as reader:
                self.assertTrue(reader.nano)
                records = list(reader)
            actual = [(metadata.sec, metadata.usec) for _, metadata in records]
            self.assertEqual(actual, [(1700000000, 123456789), (1700000001, 1), (0, 999999999)])
            self.assertEqual([p.time for p in rdpcap(str(path))], times)

    def test_truncated_capture_preserves_distinct_wire_length(self):
        """捕获长度与线上原始长度不同时分别保留。"""
        full = bytes(ethernet_packet(b"x" * 200))
        packet = Ether(full[:60])
        packet.wirelen = len(full)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "truncated.pcap"
            self.assertEqual(self.save(path, [packet]).error, "")
            with RawPcapReader(str(path)) as reader:
                self.assertGreaterEqual(reader.snaplen, 60)
                raw, metadata = next(reader)
            self.assertEqual(raw, full[:60])
            self.assertEqual((metadata.caplen, metadata.wirelen), (60, len(full)))

    def test_dlt_null_zero_is_a_valid_link_type(self):
        """合法的 DLT_NULL 数值 0 不得被当成缺失类型。"""
        packet = Loopback() / IP(src="192.0.2.1", dst="192.0.2.2") / Raw(b"loopback")
        self.assertEqual(conf.l2types.layer2num.get(type(packet)), 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "null.pcap"
            self.assertEqual(self.save(path, [packet]).error, "")
            with RawPcapReader(str(path)) as reader:
                self.assertEqual(reader.linktype, 0)
                self.assertEqual(next(reader)[0], bytes(packet))

    def test_mixed_and_unknown_link_types_are_rejected(self):
        """无法表达的链路类型被拒绝且保留旧目标。"""
        cases = [([ethernet_packet(), Loopback() / Raw(b"loop")], "混合链路"), ([Raw(b"unknown")], "链路类型")]
        for packets, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "existing.pcap"
                path.write_bytes(b"original file")
                self.assertIn(message, self.save(path, packets).error)
                self.assertEqual(path.read_bytes(), b"original file")
                self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_write_or_replace_failure_keeps_original_and_cleans_temp(self):
        """写入和原子替换失败均不破坏旧目标或遗留临时文件。"""
        for target in ("capture_engine.PcapWriter.write_packet", "capture_engine.os.replace"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "existing.pcap"
                path.write_bytes(b"original file")
                packet = ethernet_packet()
                original = bytes(packet)
                with patch(target, side_effect=OSError("simulated disk error")) as failing:
                    worker = self.save(path, [packet])
                failing.assert_called_once()
                self.assertIn("simulated disk error", worker.error)
                self.assertEqual(path.read_bytes(), b"original file")
                self.assertEqual(bytes(packet), original)
                self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_empty_snapshot_produces_a_readable_empty_pcap(self):
        """空数据集也写出可读取的合法全局文件头。"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.pcap"
            self.assertEqual(self.save(path, []).error, "")
            with RawPcapReader(str(path)) as reader:
                self.assertEqual(list(reader), [])
                self.assertEqual(reader.linktype, 1)

    def test_invalid_timestamps_and_wire_lengths_preserve_target(self):
        """无效记录元数据不得覆盖已经存在的捕获文件。"""
        cases = [("time", Decimal(value)) for value in ("-1", "NaN", "Infinity", "4294967296")]
        cases.extend(("wirelen", value) for value in (1, 0x100000000))
        for name, value in cases:
            with self.subTest(name=name, value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "existing.pcap"
                path.write_bytes(b"original file")
                packet = ethernet_packet()
                setattr(packet, name, value)
                self.assertTrue(self.save(path, [packet]).error)
                self.assertEqual(path.read_bytes(), b"original file")
                self.assertEqual(list(Path(directory).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
