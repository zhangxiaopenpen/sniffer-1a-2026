"""经典 PCAP 文件格式、容量与取消行为测试。"""

import os
import struct
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from helpers import app, wait_until
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw

from capture_engine import SaveWorker
from pcap_io import LoadWorker, MAX_RECORD_BYTES


def pcap_bytes(packets=(), endian="<", nano=False, linktype=1, snaplen=65535, version=(2, 4)):
    """构造独立于被测读取器的经典 PCAP 二进制。"""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    result = struct.pack(endian + "IHHIIII", magic, *version, 0, 0, snaplen, linktype)
    for index, raw in enumerate(packets):
        result += struct.pack(endian + "IIII", 1700000000 + index, 123456789 if nano else 123456, len(raw), len(raw)) + raw
    return result


def samples():
    """固定文档地址的以太网测试包。"""
    return [bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.1", dst="192.0.2.2")/TCP(dport=443)/Raw(b"hello")), bytes(Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:04")/IPv6(src="2001:db8::1", dst="2001:db8::2")/UDP(dport=53)/Raw(b"dns"))]


class PcapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = app()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "输入抓包.pcap"

    def tearDown(self):
        self.directory.cleanup()

    def load(self, data, **options):
        self.path.write_bytes(data)
        worker = LoadWorker(str(self.path), **options)
        worker.start()
        self.assertTrue(wait_until(worker.isFinished))
        self.assertTrue(worker.wait(100))
        return worker

    def assert_error(self, worker):
        self.assertTrue(worker.error)
        self.assertEqual(worker.packets, [])
        self.assertEqual(worker.loaded_bytes, 0)
        self.assertFalse(worker.limited)

    def test_four_magics_preserve_original_bytes_count_and_exact_timestamps(self):
        raw = samples()
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    worker = self.load(pcap_bytes(raw, endian, nano))
                    self.assertEqual(worker.error, "")
                    self.assertEqual([bytes(p) for p in worker.packets], raw)
                    self.assertEqual(worker.loaded_bytes, sum(map(len, raw)))
                    self.assertEqual(worker.linktype, 1)
                    fraction = Decimal("0.123456789" if nano else "0.123456")
                    for index, packet in enumerate(worker.packets):
                        self.assertEqual(packet.time, Decimal(1700000000 + index) + fraction)
                    self.assertFalse(worker.limited)

    def test_valid_empty_pcap_and_invalid_empty_file(self):
        worker = self.load(pcap_bytes())
        self.assertEqual((worker.error, worker.packets, worker.loaded_bytes), ("", [], 0))
        self.assertFalse(worker.limited)
        self.assert_error(self.load(b""))

    def test_packet_budget_reports_prefix_only_when_more_records_exist(self):
        raw = samples()
        exact = self.load(pcap_bytes(raw), max_packets=2)
        self.assertFalse(exact.limited)
        prefix = self.load(pcap_bytes(raw), max_packets=1)
        self.assertEqual(prefix.error, "")
        self.assertTrue(prefix.limited)
        self.assertEqual([bytes(p) for p in prefix.packets], raw[:1])
        self.assertIn("未校验", prefix.warning)

    def test_byte_budget_exact_and_first_record_exceeds_budget(self):
        raw = samples()
        exact = self.load(pcap_bytes(raw[:1]), max_bytes=len(raw[0]))
        self.assertEqual(exact.error, "")
        self.assertFalse(exact.limited)
        prefix = self.load(pcap_bytes(raw), max_bytes=len(raw[0]))
        self.assertTrue(prefix.limited)
        self.assertEqual(len(prefix.packets), 1)
        empty_prefix = self.load(pcap_bytes(raw), max_bytes=len(raw[0])-1)
        self.assertEqual(empty_prefix.error, "")
        self.assertEqual(empty_prefix.packets, [])
        self.assertTrue(empty_prefix.limited)

    def test_rejects_wrong_magic_version_snaplen_linktype_and_pcapng(self):
        cases = [
            b"garbage" + b"\0" * 20,
            pcap_bytes(version=(2, 3)), pcap_bytes(snaplen=0),
            pcap_bytes(linktype=0x12345678), pcap_bytes(linktype=0x04000001),
            b"\x0a\x0d\x0d\x0a" + b"\0" * 24,
        ]
        for data in cases:
            with self.subTest(header=data[:24]):
                self.assert_error(self.load(data))

    def test_truncated_global_header_record_header_and_packet_body(self):
        raw = samples()[0]
        cases = [pcap_bytes()[:23], pcap_bytes() + b"\0" * 15, pcap_bytes([raw])[:-1]]
        for data in cases:
            with self.subTest(length=len(data)):
                self.assert_error(self.load(data))

    def test_failure_after_valid_packet_does_not_publish_partial_result(self):
        data = pcap_bytes(samples()[:1]) + b"truncated"
        self.assert_error(self.load(data))

    def test_rejects_bad_lengths_timestamp_and_giant_declaration(self):
        raw = samples()[0]
        cases = [
            (len(raw)+1, len(raw), 0, 65535),
            (len(raw), len(raw), 0, len(raw)-1),
            (len(raw), len(raw), 1000000, 65535),
            (MAX_RECORD_BYTES+1, MAX_RECORD_BYTES+1, 0, MAX_RECORD_BYTES+1),
            (0x7FFFFFFF, 0x7FFFFFFF, 0, 0x7FFFFFFF),
        ]
        for captured, original, fraction, snaplen in cases:
            with self.subTest(captured=captured, original=original, fraction=fraction):
                data = pcap_bytes(snaplen=snaplen) + struct.pack("<IIII", 1700000000, fraction, captured, original) + raw
                self.assert_error(self.load(data))

    def test_captured_truncation_metadata_is_preserved(self):
        raw = samples()[0]
        data = pcap_bytes() + struct.pack("<IIII", 1700000000, 10, len(raw), len(raw)+100) + raw
        worker = self.load(data)
        self.assertEqual(worker.error, "")
        self.assertEqual(bytes(worker.packets[0]), raw)
        self.assertEqual(worker.packets[0].wirelen, len(raw)+100)

    def test_cancellation_before_start_publishes_no_result(self):
        self.path.write_bytes(pcap_bytes(samples()))
        worker = LoadWorker(str(self.path))
        worker.request_cancel()
        worker.start()
        self.assertTrue(wait_until(worker.isFinished))
        self.assertTrue(worker.cancelled)
        self.assertEqual((worker.error, worker.packets, worker.loaded_bytes), ("", [], 0))

    def test_cancellation_mid_read_discards_partial_work(self):
        class CancelAfterFirstPacket(LoadWorker):
            def _check_cancel(self):
                self.checks = getattr(self, "checks", 0) + 1
                if self.checks == 5:
                    self.request_cancel()
                super()._check_cancel()
        self.path.write_bytes(pcap_bytes(samples() * 100))
        worker = CancelAfterFirstPacket(str(self.path))
        worker.start()
        self.assertTrue(wait_until(worker.isFinished))
        self.assertTrue(worker.cancelled)
        self.assertEqual((worker.error, worker.packets, worker.loaded_bytes), ("", [], 0))

    def test_file_change_during_load_is_rejected(self):
        original_fstat = os.fstat
        calls = []
        def changing_stat(fd):
            result = original_fstat(fd)
            calls.append(result)
            if len(calls) == 2:
                return SimpleNamespace(st_size=result.st_size+1, st_mtime_ns=result.st_mtime_ns)
            return result
        with patch("pcap_io.os.fstat", side_effect=changing_stat):
            worker = self.load(pcap_bytes(samples()))
        self.assert_error(worker)

    def test_loaded_microsecond_file_can_be_saved_without_packet_changes(self):
        loaded = self.load(pcap_bytes(samples()))
        self.assertEqual(loaded.error, "")
        output = Path(self.directory.name) / "另存.pcap"
        save = SaveWorker(str(output), loaded.packets)
        save.start()
        self.assertTrue(wait_until(save.isFinished))
        self.assertEqual(save.error, "")
        reloaded = LoadWorker(str(output))
        reloaded.start()
        self.assertTrue(wait_until(reloaded.isFinished))
        self.assertEqual(reloaded.error, "")
        self.assertEqual([bytes(p) for p in reloaded.packets], [bytes(p) for p in loaded.packets])
        self.assertEqual([p.time for p in reloaded.packets], [p.time for p in loaded.packets])

    def test_nanosecond_second_boundary_survives_save_without_float_rounding(self):
        data = bytearray(pcap_bytes(samples()[:1], nano=True))
        data[28:32] = struct.pack("<I", 999999999)
        loaded = self.load(bytes(data))
        expected_time = Decimal("1700000000.999999999")
        self.assertEqual(loaded.error, "")
        self.assertEqual(loaded.packets[0].time, expected_time)
        output = Path(self.directory.name) / "纳秒边界.pcap"
        save = SaveWorker(str(output), loaded.packets)
        save.start()
        self.assertTrue(wait_until(save.isFinished))
        self.assertEqual(save.error, "")
        raw_output = output.read_bytes()
        magics = {b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
        self.assertIn(raw_output[:4], magics)
        endian = magics[raw_output[:4]]
        seconds, nanoseconds = struct.unpack(endian + "II", raw_output[24:32])
        self.assertEqual((seconds, nanoseconds), (1700000000, 999999999))
        reloaded = LoadWorker(str(output))
        reloaded.start()
        self.assertTrue(wait_until(reloaded.isFinished))
        self.assertEqual(reloaded.error, "")
        self.assertEqual(reloaded.packets[0].time, expected_time)
        self.assertEqual(bytes(reloaded.packets[0]), bytes(loaded.packets[0]))

    def test_large_packet_export_snaplen_and_roundtrip(self):
        raw = bytes(Ether(src="02:00:00:00:00:05", dst="02:00:00:00:00:06", type=0x88B5)/Raw(b"x" * 70000))
        loaded = self.load(pcap_bytes([raw], snaplen=len(raw)))
        self.assertEqual(loaded.error, "")
        self.assertGreater(len(raw), 65535)
        output = Path(self.directory.name) / "大包.pcap"
        save = SaveWorker(str(output), loaded.packets)
        save.start()
        self.assertTrue(wait_until(save.isFinished))
        self.assertEqual(save.error, "")
        raw_output = output.read_bytes()
        endian = "<" if raw_output[:4] in (b"\x4d\x3c\xb2\xa1", b"\xd4\xc3\xb2\xa1") else ">"
        snaplen = struct.unpack(endian + "I", raw_output[16:20])[0]
        self.assertGreaterEqual(snaplen, len(raw))
        reloaded = LoadWorker(str(output))
        reloaded.start()
        self.assertTrue(wait_until(reloaded.isFinished))
        self.assertEqual(reloaded.error, "")
        self.assertEqual(len(reloaded.packets), 1)
        self.assertEqual(bytes(reloaded.packets[0]), raw)


if __name__ == "__main__":
    unittest.main()
