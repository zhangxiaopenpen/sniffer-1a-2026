import threading
import unittest

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP

from domain_analysis import AnalysisCancelled, _build_analysis_stats, analyze_packets
from domain_models import AnalysisBudget, AnalysisResult, AnalysisStats, DomainEvidence, EvidenceSource
from domain_parsers import analyze_packet, normalize_domain


def _dns_query(txid=7, name="www.example.test", sport=53000):
    packet = Ether(src="30:7b:ac:69:38:02", dst="9c:67:d6:c8:2f:0d") / IP(
        src="10.0.0.2", dst="8.8.8.8"
    ) / UDP(sport=sport, dport=53) / DNS(id=txid, qd=DNSQR(qname=name, qtype="A"))
    return packet


def _dns_response(txid=7, name="www.example.test", sport=53000, address="203.0.113.10"):
    packet = Ether(src="9c:67:d6:c8:2f:0d", dst="30:7b:ac:69:38:02") / IP(
        src="8.8.8.8", dst="10.0.0.2"
    ) / UDP(sport=53, dport=sport) / DNS(
        id=txid,
        qr=1,
        qd=DNSQR(qname=name, qtype="A"),
        an=DNSRR(rrname=name, type="A", ttl=30, rdata=address),
    )
    return packet


def _http_host_packet(name="www.example.test", sport=50000):
    """构造单包完整 HTTP Host 证据。"""
    return Ether() / IP(src="10.0.0.2", dst="203.0.113.10") / TCP(
        sport=sport, dport=80, flags="PA"
    ) / Raw(load=f"GET / HTTP/1.1\r\nHost: {name}\r\n\r\n".encode("ascii"))


def _tls_sni_packet(name="www.example.test", sport=50001):
    """构造单包完整 TLS ClientHello SNI 证据。"""
    name_bytes = name.encode("ascii")
    sni_data = (
        (len(name_bytes) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(name_bytes).to_bytes(2, "big")
        + name_bytes
    )
    extension = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
    hello = (
        b"\x03\x03" + bytes(32) + b"\x00" + (2).to_bytes(2, "big") + b"\x13\x01"
        + b"\x01\x00" + len(extension).to_bytes(2, "big") + extension
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    return Ether() / IP(src="10.0.0.2", dst="203.0.113.10") / TCP(
        sport=sport, dport=443, flags="PA"
    ) / Raw(load=record)


class DomainParserTests(unittest.TestCase):
    def test_normalize_and_http_host(self):
        self.assertEqual(normalize_domain("WWW.Example.Test."), "www.example.test")
        packet = Ether() / IP(src="10.0.0.2", dst="203.0.113.10") / TCP(
            sport=50000, dport=80, flags="PA"
        ) / Raw(load=b"GET / HTTP/1.1\r\nHost: WWW.Example.Test\r\n\r\n")
        result = analyze_packet(packet, 3)
        self.assertEqual(result.evidence[0].domain, "www.example.test")
        self.assertEqual(result.evidence[0].source, EvidenceSource.HTTP_HOST)

    def test_dns_query_response_metadata(self):
        query, response = _dns_query(), _dns_response()
        query.time, response.time = 100.0, 100.2
        result = analyze_packets([query, response])
        self.assertEqual(len(result.transactions), 1)
        self.assertTrue(result.transactions[0].matched)
        self.assertEqual(result.transactions[0].query.transaction_id, 7)
        self.assertEqual(result.transactions[0].response.answers[0].value, "203.0.113.10")
        self.assertEqual(result.row_text(0)[0], "www.example.test")

    def test_mismatch_does_not_associate(self):
        query, response = _dns_query(txid=1), _dns_response(txid=2)
        query.time, response.time = 100.0, 100.2
        result = analyze_packets([query, response])
        self.assertFalse(result.transactions[0].matched)
        self.assertIn("未匹配", result.notes[1])

    def test_candidate_is_excluded_by_default(self):
        query, response = _dns_query(), _dns_response()
        later = Ether() / IP(src="10.0.0.2", dst="203.0.113.10") / TCP(
            sport=50001, dport=443, flags="A"
        ) / Raw(load=b"x")
        query.time, response.time, later.time = 100.0, 100.1, 100.5
        result = analyze_packets([query, response, later])
        self.assertTrue(any(item.confidence == "candidate" for item in result.row_evidence(2)))
        self.assertNotIn(2, result.rows_for_domain("www.example.test"))
        self.assertIn(2, result.rows_for_domain("www.example.test", include_candidates=True))

    def test_cross_packet_http_does_not_create_evidence(self):
        first = Ether() / IP() / TCP(sport=50000, dport=80, flags="PA") / Raw(
            load=b"GET / HTTP/1.1\r\nHo"
        )
        second = Ether() / IP() / TCP(sport=50000, dport=80, flags="PA") / Raw(
            load=b"st: example.test\r\n\r\n"
        )
        self.assertFalse(analyze_packet(first, 0).evidence)
        self.assertFalse(analyze_packet(second, 1).evidence)

    def test_tls_clienthello_sni_is_single_packet_evidence(self):
        name = b"www.example.test"
        sni_data = (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
        extension = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
        hello = (
            b"\x03\x03" + bytes(32) + b"\x00" + (2).to_bytes(2, "big") + b"\x13\x01"
            + b"\x01\x00" + len(extension).to_bytes(2, "big") + extension
        )
        handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
        record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
        packet = Ether() / IP() / TCP(sport=50000, dport=443, flags="PA") / Raw(load=record)
        result = analyze_packet(packet, 0)
        self.assertEqual(result.evidence[0].source, EvidenceSource.TLS_SNI)
        self.assertEqual(result.evidence[0].domain, "www.example.test")

    def test_budget_and_cancel(self):
        packet = _dns_query()
        with self.assertRaises(ValueError):
            analyze_packets([packet], budget=AnalysisBudget(max_packets=0))
        event = threading.Event()
        event.set()
        with self.assertRaises(AnalysisCancelled):
            analyze_packets([packet], cancel_event=event)

    def test_malformed_dns_isolated_as_note(self):
        packet = Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(load=b"\xff" * 32)
        result = analyze_packet(packet, 0)
        self.assertFalse(result.evidence)
        self.assertTrue(result.note)


class DomainAnalysisStatsTests(unittest.TestCase):
    def test_matched_query_response_populates_all_stats(self):
        query, response = _dns_query(), _dns_response()
        query.time, response.time = 100.0, 100.2

        result = analyze_packets([query, response])

        self.assertEqual(
            result.stats,
            AnalysisStats(
                query_count=1,
                response_count=1,
                matched_transaction_count=1,
                unmatched_query_count=0,
                unique_domain_count=1,
            ),
        )

    def test_query_only_is_counted_as_unmatched(self):
        query = _dns_query()
        query.time = 100.0

        result = analyze_packets([query])

        self.assertEqual(
            result.stats,
            AnalysisStats(
                query_count=1,
                response_count=0,
                matched_transaction_count=0,
                unmatched_query_count=1,
                unique_domain_count=1,
            ),
        )

    def test_invalid_response_key_keeps_response_and_unmatched_query_counts(self):
        cases = (
            ("transaction id", _dns_response(txid=8), 100.2),
            ("endpoint", _dns_response(), 100.2),
            ("qname", _dns_response(name="api.example.test"), 100.2),
            ("time window", _dns_response(), 131.0),
        )
        for label, response, response_time in cases:
            with self.subTest(label=label):
                query = _dns_query()
                query.time, response.time = 100.0, response_time
                if label == "endpoint":
                    response[IP].src = "1.1.1.1"

                result = analyze_packets([query, response])

                self.assertEqual(result.stats.query_count, 1)
                self.assertEqual(result.stats.response_count, 1)
                self.assertEqual(result.stats.matched_transaction_count, 0)
                self.assertEqual(result.stats.unmatched_query_count, 1)
                self.assertFalse(result.transactions[0].matched)

    def test_orphan_response_does_not_become_an_unmatched_query(self):
        response = _dns_response()
        response.time = 100.0

        result = analyze_packets([response])

        self.assertEqual(
            result.stats,
            AnalysisStats(
                query_count=0,
                response_count=1,
                matched_transaction_count=0,
                unmatched_query_count=0,
                unique_domain_count=1,
            ),
        )
        self.assertEqual(len(result.transactions), 1)
        self.assertTrue(result.transactions[0].query.is_response)

    def test_repeated_direct_evidence_from_dns_http_and_tls_counts_once(self):
        query, response = _dns_query(), _dns_response()
        http = _http_host_packet()
        duplicate_http = _http_host_packet(sport=50002)
        tls = _tls_sni_packet()
        query.time, response.time = 100.0, 100.2
        http.time, duplicate_http.time, tls.time = 100.3, 100.4, 100.5

        result = analyze_packets([query, response, http, duplicate_http, tls])

        self.assertEqual(result.stats.unique_domain_count, 1)
        direct_domains = {
            evidence.domain
            for evidence_items in result.rows.values()
            for evidence in evidence_items
            if evidence.confidence == "direct"
        }
        self.assertEqual(direct_domains, {"www.example.test"})

    def test_dns_candidate_is_excluded_from_unique_domain_count(self):
        query, response = _dns_query(), _dns_response()
        later = Ether() / IP(src="10.0.0.2", dst="203.0.113.10") / TCP(
            sport=50003, dport=443, flags="A"
        ) / Raw(load=b"x")
        query.time, response.time, later.time = 100.0, 100.1, 100.5

        result = analyze_packets([query, response, later])

        self.assertTrue(any(item.confidence == "candidate" for item in result.row_evidence(2)))
        self.assertEqual(result.stats.unique_domain_count, 1)
        candidate_only = DomainEvidence(
            "unseen.example.test", EvidenceSource.DNS_CANDIDATE, 99, confidence="candidate"
        )
        stats = _build_analysis_stats(
            result.dns_messages,
            result.transactions,
            {**result.rows, 99: (candidate_only,)},
        )
        self.assertEqual(stats.unique_domain_count, 1)

    def test_analysis_stats_defaults_and_rejects_negative_values(self):
        self.assertEqual(AnalysisStats(), AnalysisStats(0, 0, 0, 0, 0))
        self.assertEqual(AnalysisResult(generation=1).stats, AnalysisStats())
        with self.assertRaises(ValueError):
            AnalysisStats(query_count=-1)


if __name__ == "__main__":
    unittest.main()
