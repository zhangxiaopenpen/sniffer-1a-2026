"""TCP 流后台分析的快照、资源限额、会话和原包不变验证。"""

import unittest
from dataclasses import replace
from threading import Event
from unittest.mock import patch

from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw

from domain_models import AnalysisSnapshot
from examples.make_stream_demo import build_demo_packets, make_client_hello
from stream_analysis import (
    StreamAnalysisCancelled, StreamAnalysisWorker, analyze_streams,
)
from stream_models import StreamBudget


REQUEST = b"GET / HTTP/1.1\r\nHost: stream.example.test\r\n\r\n"


def packet(sequence, payload=b"", flags="PA", port=51000, reverse=False, ipv6=False):
    """创建无网络操作的独立 TCP 包，并固定原始字节。"""
    source, destination = (("2001:db8::10", "2001:db8::20") if ipv6
                           else ("192.0.2.10", "192.0.2.20"))
    sport, dport = port, 80
    if reverse:
        source, destination = destination, source
        sport, dport = dport, sport
    network = IPv6(src=source, dst=destination) if ipv6 else IP(src=source, dst=destination)
    value = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20") / network / TCP(
        sport=sport, dport=dport, seq=sequence, flags=flags,
    )
    if payload:
        value /= Raw(payload)
    return Ether(bytes(value))


def connection(port=51000, request=REQUEST):
    """返回含双向 SYN 的连接与跨段请求。"""
    cut = request.index(b"example") if b"example" in request else 10
    return [packet(100, flags="S", port=port),
            packet(900, flags="SA", port=port, reverse=True),
            packet(101, request[:cut], port=port),
            packet(101 + cut, request[cut:], port=port)]


class StreamPipelineTests(unittest.TestCase):
    def test_demo_has_five_sessions_and_exactly_two_confirmed_domains(self):
        packets = build_demo_packets()
        result = analyze_streams(packets)
        self.assertEqual(len(packets), 31)
        self.assertEqual(len(result.flows), 5)
        self.assertEqual([flow.domains for flow in result.flows], [
            ("www.stage5.example.test",), ("tls.stage5.example.test",), (), (), (),
        ])
        self.assertIn("缺口", result.flows[2].status)
        self.assertIn("冲突", result.flows[3].status)
        self.assertIn("起点未知", result.flows[4].status)
        self.assertGreater(result.flows[0].retransmitted_bytes, 0)
        self.assertIn("[2001:db8::10]", result.flows[1].endpoint_text)
        for row in range(31):
            self.assertTrue(result.row_text(row)[0])

    def test_snapshot_metadata_and_original_packets_are_preserved(self):
        packets = build_demo_packets()
        original = [(id(item), item.original, bytes(item), repr(item.fields), item.time)
                    for item in packets]
        snapshot = AnalysisSnapshot(9, tuple(packets), "test-dataset")
        result = analyze_streams(snapshot)
        self.assertEqual(result.generation, 9)
        self.assertEqual(result.dataset_id, "test-dataset")
        self.assertEqual(result.packet_identity, tuple(id(item) for item in packets))
        after = [(id(item), item.original, bytes(item), repr(item.fields), item.time)
                 for item in packets]
        self.assertEqual(after, original)

    def test_source_rows_include_control_packets_but_non_tcp_columns_stay_empty(self):
        packets = connection()
        packets.insert(1, Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20") /
                       IP(src="192.0.2.1", dst="192.0.2.2") / UDP())
        result = analyze_streams(packets)
        self.assertEqual(result.row_text(1), ("", "", ""))
        self.assertEqual(result.flows[0].packet_rows, (0, 2, 3, 4))
        self.assertNotEqual(result.row_text(0)[1], result.row_text(2)[1])
        self.assertEqual(result.flows[0].evidence[0].packet_indices, (3, 4))
        self.assertIn("#4", result.detail_text(0))
        self.assertIn("#5", result.detail_text(0))

    def test_negative_or_disordered_timestamps_do_not_change_session_order(self):
        packets = connection()
        for item, timestamp in zip(packets, (50, float("nan"), -100, 0)):
            item.time = timestamp
        result = analyze_streams(packets)
        self.assertEqual(len(result.flows), 1)
        self.assertEqual(result.flows[0].packet_rows, tuple(range(4)))
        self.assertEqual(result.flows[0].domains, ("stream.example.test",))

    def test_new_syn_preserves_both_previous_and_new_session_rows(self):
        first = connection()
        second = [packet(1000, flags="S"), packet(1001, REQUEST)]
        result = analyze_streams(first + second)
        self.assertEqual(len(result.flows), 2)
        self.assertEqual(result.flows[0].packet_rows, (0, 1, 2, 3))
        self.assertEqual(result.flows[1].packet_rows, (4, 5))
        self.assertEqual(result.flows[1].session_id, result.flows[0].session_id + 1)
        self.assertTrue(all(flow.domains for flow in result.flows))

    def test_same_isn_after_reset_starts_new_session(self):
        packets = connection() + [packet(901, flags="RA", reverse=True)] + connection()
        result = analyze_streams(packets)
        self.assertEqual(len(result.flows), 2)
        self.assertEqual(result.flows[0].packet_rows, tuple(range(5)))
        self.assertEqual(result.flows[1].packet_rows, tuple(range(5, 9)))

    def test_payload_after_rst_or_fin_cannot_borrow_previous_syn(self):
        cases = (
            [packet(100, flags="S"), packet(101, flags="RA")],
            [packet(100, flags="S"), packet(900, flags="SA", reverse=True),
             packet(101, flags="FA"), packet(901, flags="FA", reverse=True)],
            [packet(100, flags="S"), packet(900, flags="SA", reverse=True),
             packet(101, flags="FA")],
        )
        for prior in cases:
            with self.subTest(boundary=len(prior)):
                result = analyze_streams(prior + [packet(102, REQUEST)])
                self.assertEqual(len(result.flows), 2)
                self.assertEqual(result.flows[1].packet_rows, (len(prior),))
                self.assertFalse(result.flows[1].domains)
                self.assertIn("起点未知", result.flows[1].status)

    def test_reverse_direction_conflict_suppresses_whole_flow_evidence(self):
        packets = connection() + [packet(901, b"abcd", reverse=True),
                                  packet(901, b"Xbcd", reverse=True)]
        result = analyze_streams(packets)
        self.assertFalse(result.flows[0].domains)
        self.assertFalse(result.flows[0].evidence)
        self.assertFalse(result.rows)
        self.assertIn("冲突", result.flows[0].status)

    def test_synack_only_capture_does_not_confirm_client_request(self):
        for payload in (REQUEST, make_client_hello("tls.example.test")):
            with self.subTest(payload=payload[:10]):
                result = analyze_streams([packet(900, flags="SA", reverse=True),
                                          packet(901, payload, reverse=True)])
                self.assertFalse(result.flows[0].domains)
                self.assertFalse(result.rows)

    def test_conflicting_synack_blocks_healthy_client_direction_evidence(self):
        result = analyze_streams(connection() + [packet(3000, flags="SA", reverse=True)])
        self.assertFalse(result.flows[0].domains)
        self.assertFalse(result.rows)
        self.assertIn("冲突", result.flows[0].status)

    def test_input_budget_stops_an_unbounded_generator(self):
        consumed = 0
        value = packet(100, flags="S")

        def generate():
            nonlocal consumed
            while True:
                consumed += 1
                yield value

        with self.assertRaises(ValueError):
            analyze_streams(generate(), budget=StreamBudget(max_packets=3))
        self.assertLessEqual(consumed, 4)

    def test_flow_count_limit_never_merges_new_session_into_old_one(self):
        packets = connection() + [packet(1000, flags="S"), packet(1001, REQUEST)]
        result = analyze_streams(packets, budget=StreamBudget(max_flows=1))
        self.assertEqual(len(result.flows), 1)
        self.assertEqual(result.flows[0].packet_rows, (0, 1, 2, 3))
        self.assertEqual(result.row_text(4), ("", "", ""))
        self.assertEqual(result.row_text(5), ("", "", ""))
        self.assertTrue(result.warning)

    def test_segment_limit_retains_rows_but_blocks_domains(self):
        packets = connection()
        result = analyze_streams(packets, budget=StreamBudget(max_segments_per_flow=3))
        self.assertEqual(result.flows[0].packet_rows, tuple(range(4)))
        self.assertEqual(len(result.row_streams), 4)
        self.assertFalse(result.flows[0].domains)
        self.assertIn("限额", result.flows[0].status)

    def test_direction_budget_exact_boundary_and_overflow(self):
        exact = analyze_streams(connection(), budget=StreamBudget(max_direction_bytes=len(REQUEST)))
        self.assertEqual(exact.flows[0].domains, ("stream.example.test",))
        small = analyze_streams(connection(), budget=StreamBudget(max_direction_bytes=len(REQUEST) - 1))
        self.assertFalse(small.flows[0].domains)
        self.assertIn("限额", small.flows[0].status)

    def test_total_payload_budget_spans_sessions(self):
        packets = connection(51000) + connection(51001)
        result = analyze_streams(packets, budget=StreamBudget(max_total_bytes=2 * len(REQUEST) - 1))
        self.assertEqual(result.flows[0].domains, ("stream.example.test",))
        self.assertFalse(result.flows[1].domains)
        self.assertIn("限额", result.flows[1].status)
        self.assertTrue(result.warning)
        self.assertEqual(len(result.row_streams), 8)

    def test_empty_and_malformed_input_do_not_invent_flows(self):
        self.assertEqual(analyze_streams([]).flows, ())
        broken = Ether(bytes(Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20") /
                             IP(src="192.0.2.1", dst="192.0.2.2") /
                             TCP(sport=51000, dport=80, dataofs=4)))
        result = analyze_streams([broken])
        self.assertEqual(result.flows, ())
        self.assertEqual(result.row_text(0), ("", "", ""))
        self.assertTrue(result.notes[0])

    def test_unserializable_scapy_packet_is_skipped_without_losing_good_flow(self):
        bad = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=999999, dport=80)
        result = analyze_streams([bad] + connection())
        self.assertTrue(result.notes[0])
        self.assertEqual(result.flows[0].domains, ("stream.example.test",))
        self.assertEqual(result.row_text(0), ("", "", ""))

    def test_sparse_sequence_window_limit_surfaces_global_warning(self):
        result = analyze_streams([packet(100, flags="S"), packet(1_000_000, b"x")],
                                 budget=StreamBudget(max_direction_bytes=64))
        self.assertFalse(result.flows[0].domains)
        self.assertIn("限额", result.flows[0].status)
        self.assertTrue(result.warning)

    def test_cancel_after_collection_and_at_completion_returns_no_result(self):
        for threshold in (40, 100):
            with self.subTest(threshold=threshold):
                event = Event()

                def progress(value):
                    if value >= threshold:
                        event.set()

                with self.assertRaises(StreamAnalysisCancelled):
                    analyze_streams(connection(), event, progress)

    def test_cancel_before_start_and_invalid_budget_fields(self):
        event = Event()
        event.set()
        with self.assertRaises(StreamAnalysisCancelled):
            analyze_streams(connection(), event)
        for name in StreamBudget.__dataclass_fields__:
            for value in (0, -1, True, 1.5):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    replace(StreamBudget(), **{name: value})

    def test_detail_limits_packet_list_without_losing_total(self):
        packets = [packet(100, flags="S")] + [packet(101, flags="A") for _ in range(120)]
        result = analyze_streams(packets)
        detail = result.detail_text(120)
        self.assertIn("121", detail)
        self.assertNotIn("#121", detail)
        self.assertLess(len(detail), 5000)


class StreamWorkerTests(unittest.TestCase):
    def test_worker_publishes_complete_snapshot(self):
        snapshot = AnalysisSnapshot(4, tuple(connection()), "worker-test")
        worker = StreamAnalysisWorker(snapshot)
        worker.start()
        self.assertTrue(worker.wait(5000))
        self.assertFalse(worker.error)
        self.assertFalse(worker.cancelled)
        self.assertEqual(worker.progress, 100)
        self.assertEqual(worker.result.generation, 4)
        self.assertEqual(worker.result.flows[0].domains, ("stream.example.test",))

    def test_worker_budget_error_does_not_publish_partial_result(self):
        worker = StreamAnalysisWorker(AnalysisSnapshot(0, tuple(connection())),
                                      budget=StreamBudget(max_packets=1))
        worker.start()
        self.assertTrue(worker.wait(5000))
        self.assertTrue(worker.error)
        self.assertIsNone(worker.result)

    def test_worker_cancel_during_parsing_discards_completed_result(self):
        from tcp_application import parse_stream_payload

        entered, release = Event(), Event()

        def controlled_parse(payload):
            entered.set()
            release.wait(3)
            return parse_stream_payload(payload)

        worker = StreamAnalysisWorker(AnalysisSnapshot(0, tuple(connection())))
        try:
            with patch("stream_analysis.parse_stream_payload", controlled_parse):
                worker.start()
                self.assertTrue(entered.wait(3))
                worker.request_cancel()
                release.set()
                self.assertTrue(worker.wait(5000))
        finally:
            release.set()
            worker.request_cancel()
            worker.wait(5000)
        self.assertTrue(worker.cancelled)
        self.assertFalse(worker.error)
        self.assertIsNone(worker.result)


if __name__ == "__main__":
    unittest.main()
