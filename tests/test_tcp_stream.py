"""TCP 序号、会话边界和有界重组的离线回归测试。"""

import tracemalloc
import unittest

from tcp_models import (
    UINT32_HALF, UINT32_MODULUS, TcpDirection, TcpEndpoint, TcpFlow,
    TcpFlowKey, TcpSegment, TcpSessionState, unwrap_sequence,
)
from tcp_reassembly import assemble_flow, reassemble_direction


FORWARD = TcpDirection.A_TO_B
BACKWARD = TcpDirection.B_TO_A
KEY = TcpFlowKey.from_values("192.0.2.10", 51000, "192.0.2.20", 80)


def segment(sequence, payload=b"", flags="PA", row=0, direction=FORWARD):
    """创建独立于 Scapy 的不可变 TCP 片段。"""
    return TcpSegment(KEY, direction, sequence % UINT32_MODULUS,
                      flags=frozenset(flags), payload=payload, source_packet_index=row)


class TcpModelTests(unittest.TestCase):
    def test_bidirectional_keys_and_direction_for_both_ip_versions(self):
        for source, destination in (("192.0.2.10", "192.0.2.20"),
                                    ("2001:db8::10", "2001:0db8:0:0:0:0:0:20")):
            with self.subTest(source=source):
                a, b = TcpEndpoint(source, 51000), TcpEndpoint(destination, 80)
                key = TcpFlowKey.from_endpoints(a, b)
                self.assertEqual(key, TcpFlowKey.from_endpoints(b, a))
                self.assertNotEqual(key.direction_for(a, b), key.direction_for(b, a))
                self.assertEqual(key.endpoints_for(key.direction_for(a, b)), (a, b))
        self.assertEqual(TcpEndpoint("2001:0db8::1", 80).address, "2001:db8::1")

    def test_sequence_unwrap_across_zero_in_both_directions(self):
        self.assertEqual(unwrap_sequence(3, UINT32_MODULUS - 2), UINT32_MODULUS + 3)
        self.assertEqual(unwrap_sequence(UINT32_MODULUS - 2, 3), -2)
        self.assertEqual(unwrap_sequence(3, 2 * UINT32_MODULUS), 2 * UINT32_MODULUS + 3)
        with self.assertRaises(ValueError):
            unwrap_sequence(UINT32_MODULUS, 0)

    def test_live_syn_retransmission_stays_in_same_session(self):
        flow = TcpFlow(KEY)
        initial = segment(100, flags="S")
        flow.add_segment(initial)
        self.assertFalse(flow.needs_new_session(segment(100, flags="S", row=1)))
        flow.add_segment(segment(100, flags="S", row=1))
        self.assertEqual(len(flow.segments), 2)
        self.assertEqual(flow.session_id, 0)

    def test_new_initial_sequence_requires_new_container_without_erasing_old(self):
        flow = TcpFlow(KEY)
        flow.add_segment(segment(100, flags="S"))
        flow.add_segment(segment(101, b"abc", row=1))
        prior = tuple(flow.segments)
        replacement = segment(1000, flags="S", row=2)
        self.assertTrue(flow.needs_new_session(replacement))
        with self.assertRaises(ValueError):
            flow.add_segment(replacement)
        self.assertEqual(tuple(flow.segments), prior)

    def test_syn_after_midstream_payload_requires_new_session(self):
        flow = TcpFlow(KEY)
        flow.add_segment(segment(4000, b"midstream"))
        self.assertEqual(flow.state, TcpSessionState.MIDSTREAM)
        self.assertTrue(flow.needs_new_session(segment(100, flags="S", row=1)))

    def test_both_fin_and_tail_ack_keep_closed_state(self):
        flow = TcpFlow(KEY)
        for item in (segment(100, flags="S"),
                     segment(900, flags="SA", direction=BACKWARD, row=1),
                     segment(101, flags="FA", row=2)):
            flow.add_segment(item)
        self.assertEqual(flow.state, TcpSessionState.HALF_CLOSED)
        flow.add_segment(segment(901, flags="FA", direction=BACKWARD, row=3))
        flow.add_segment(segment(102, flags="A", row=4))
        self.assertEqual(flow.state, TcpSessionState.CLOSED)
        self.assertTrue(flow.needs_new_session(segment(100, flags="S", row=5)))

    def test_rst_is_terminal_and_same_isn_syn_creates_new_session(self):
        flow = TcpFlow(KEY)
        flow.add_segment(segment(100, flags="S"))
        flow.add_segment(segment(901, flags="RA", direction=BACKWARD, row=1))
        flow.add_segment(segment(101, flags="A", row=2))
        self.assertEqual(flow.state, TcpSessionState.RESET)
        self.assertTrue(flow.needs_new_session(segment(100, flags="S", row=3)))


class TcpReassemblyTests(unittest.TestCase):
    def test_out_of_order_and_retransmitted_bytes_have_stable_sources(self):
        items = [segment(100, flags="S"), segment(104, b"def", row=1),
                 segment(101, b"abc", row=2), segment(101, b"abc", row=3)]
        before = tuple(items)
        result = reassemble_direction(FORWARD, items)
        self.assertEqual(result.payload, b"abcdef")
        self.assertEqual(result.source_packet_indices, (1, 2))
        self.assertEqual((result.retransmissions, result.overlaps), (3, 3))
        self.assertTrue(result.reliable)
        self.assertEqual(tuple(items), before)

    def test_partial_consistent_overlap_extends_stream(self):
        result = reassemble_direction(FORWARD, [segment(100, flags="S"),
            segment(101, b"abcd", row=1), segment(103, b"cdef", row=2)])
        self.assertEqual(result.payload, b"abcdef")
        self.assertEqual(result.retransmissions, 2)
        self.assertFalse(result.conflict)
        self.assertTrue(result.reliable)

    def test_conflict_keeps_first_capture_and_blocks_evidence(self):
        result = reassemble_direction(FORWARD, [segment(100, flags="S"),
            segment(103, b"XYef", row=1), segment(101, b"abcd", row=2)])
        self.assertEqual(result.payload, b"abXYef")
        self.assertTrue(result.conflict)
        self.assertFalse(result.reliable)
        self.assertIn("冲突", result.status)

    def test_missing_first_payload_does_not_rebase_to_later_http(self):
        result = reassemble_direction(FORWARD, [segment(100, flags="S"),
            segment(108, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", row=1)])
        self.assertEqual(result.payload, b"")
        self.assertEqual(result.gap_ranges, ((101, 108),))
        self.assertEqual(result.source_packet_indices, ())
        self.assertFalse(result.reliable)

    def test_internal_gap_excludes_isolated_suffix_and_its_source(self):
        result = reassemble_direction(FORWARD, [segment(100, flags="S"),
            segment(101, b"abc", row=1), segment(108, b"later", row=2)])
        self.assertEqual(result.payload, b"abc")
        self.assertEqual(result.gap_ranges, ((104, 108),))
        self.assertEqual(result.source_packet_indices, (1,))
        self.assertFalse(result.complete)

    def test_fin_reveals_unseen_tail_and_no_payload_gap(self):
        for items, expected_gap in (
            ([segment(100, flags="S"), segment(101, b"abc", row=1),
              segment(110, flags="FA", row=2)], (104, 110)),
            ([segment(100, flags="S"), segment(110, flags="FA", row=1)], (101, 110)),
        ):
            with self.subTest(expected_gap=expected_gap):
                result = reassemble_direction(FORWARD, items)
                self.assertTrue(result.has_fin)
                self.assertEqual(result.gap_ranges, (expected_gap,))
                self.assertFalse(result.reliable)

    def test_fin_after_payload_is_not_application_byte_or_gap(self):
        result = reassemble_direction(FORWARD, [segment(100, flags="S"),
            segment(101, b"abc", flags="FPA", row=1)])
        self.assertEqual(result.payload, b"abc")
        self.assertEqual(result.end_sequence, 104)
        self.assertFalse(result.has_gap)
        self.assertTrue(result.complete)
        self.assertEqual(result.status, "FIN 结束")

    def test_unknown_start_does_not_publish_reliable_http(self):
        result = reassemble_direction(FORWARD, [segment(100,
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")])
        self.assertTrue(result.payload)
        self.assertFalse(result.has_syn)
        self.assertFalse(result.reliable)
        self.assertEqual(result.status, "起点未知")

    def test_wraparound_and_syn_at_last_sequence(self):
        for syn, first_seq, second_seq in (
            (UINT32_MODULUS - 3, UINT32_MODULUS - 2, 0),
            (UINT32_MODULUS - 1, 0, 2),
        ):
            with self.subTest(syn=syn):
                result = reassemble_direction(FORWARD, [segment(syn, flags="S"),
                    segment(second_seq, b"cd", row=1), segment(first_seq, b"ab", row=2)])
                self.assertEqual(result.payload, b"abcd")
                self.assertTrue(result.reliable)

    def test_payload_on_syn_uses_following_sequence(self):
        result = reassemble_direction(FORWARD, [segment(100, b"abc", flags="S"),
            segment(104, b"def", row=1)])
        self.assertEqual(result.payload, b"abcdef")
        self.assertEqual(result.start_sequence, 101)
        self.assertTrue(result.reliable)

    def test_conflicting_synack_sequences_are_ambiguous_even_without_payload(self):
        for second_sequence, expected_conflict in ((200, False), (1000, True)):
            with self.subTest(second_sequence=second_sequence):
                result = reassemble_direction(BACKWARD, [
                    segment(200, flags="SA", direction=BACKWARD),
                    segment(second_sequence, flags="SA", direction=BACKWARD, row=1),
                ])
                self.assertEqual(result.conflict, expected_conflict)
                self.assertEqual(result.complete, not expected_conflict)

    def test_half_sequence_space_is_not_reliable(self):
        result = reassemble_direction(FORWARD, [segment(100, flags="S"),
            segment(101 + UINT32_HALF, b"x", row=1)], max_bytes=64)
        self.assertTrue(result.conflict)
        self.assertFalse(result.reliable)

    def test_exact_byte_budget_and_retransmission_do_not_truncate(self):
        result = reassemble_direction(FORWARD, [segment(100, flags="S"),
            segment(101, b"abcd", row=1), segment(101, b"abcd", row=2)], max_bytes=4)
        self.assertEqual(result.payload, b"abcd")
        self.assertEqual(result.retransmissions, 4)
        self.assertFalse(result.truncated)
        self.assertTrue(result.reliable)

    def test_over_byte_or_segment_budget_marks_incomplete(self):
        items = [segment(100, flags="S"), segment(101, b"abc", row=1),
                 segment(104, b"def", row=2)]
        for limits in ({"max_bytes": 4}, {"max_segments": 2}):
            with self.subTest(limits=limits):
                result = reassemble_direction(FORWARD, items, **limits)
                self.assertTrue(result.truncated)
                self.assertFalse(result.reliable)

    def test_large_sparse_sequence_span_stays_within_memory_budget(self):
        tracemalloc.start()
        try:
            result = reassemble_direction(FORWARD, [segment(100, flags="S"),
                segment(101, b"a", row=1), segment(1_000_000_000, b"z", row=2)],
                max_bytes=4096)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 1024 * 1024)
        self.assertEqual(result.payload, b"a")
        self.assertTrue(result.truncated)
        self.assertTrue(result.has_gap)

    def test_cancellation_is_checked_within_large_segment(self):
        checks = 0

        def cancel():
            nonlocal checks
            checks += 1
            if checks == 6:
                raise InterruptedError("cancel during payload")

        with self.assertRaisesRegex(InterruptedError, "during payload"):
            reassemble_direction(FORWARD, [segment(100, flags="S"),
                segment(101, b"x" * 100_000, row=1)], cancel_check=cancel)
        self.assertEqual(checks, 6)

    def test_flow_budget_counts_both_directions(self):
        flow = TcpFlow(KEY)
        for item in (segment(100, flags="S"),
                     segment(900, flags="SA", direction=BACKWARD, row=1),
                     segment(101, b"abc", row=2)):
            flow.add_segment(item)
        result = assemble_flow(flow, max_segments=2)
        self.assertEqual(set(result.directions), {FORWARD, BACKWARD})
        self.assertTrue(all(item.truncated for item in result.directions.values()))
        with self.assertRaises(TypeError):
            result.directions[FORWARD] = None

    def test_empty_control_only_wrong_direction_and_invalid_budgets(self):
        self.assertFalse(reassemble_direction(FORWARD, []).reliable)
        control = reassemble_direction(FORWARD, [segment(100, flags="S")])
        self.assertTrue(control.complete)
        self.assertFalse(control.reliable)
        with self.assertRaises(ValueError):
            reassemble_direction(FORWARD, [segment(100, direction=BACKWARD)])
        for limits in ({"max_bytes": 0}, {"max_segments": 0}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                reassemble_direction(FORWARD, [], **limits)


if __name__ == "__main__":
    unittest.main()
