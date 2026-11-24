import unittest

from PySide6.QtCore import Qt
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

from domain_models import AnalysisResult, DomainEvidence, EvidenceSource
from main import SnifferWindow
from packet_filter import parse_filter
from packet_model import PacketTableModel
from helpers import app, wait_until


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
        self.window.close()
        self.window.deleteLater()

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


if __name__ == "__main__":
    unittest.main()
