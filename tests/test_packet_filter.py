"""显示过滤语义、隧道边界及源模型映射测试。"""

import unittest
from ipaddress import ip_network

from helpers import app
from packet_filter import FilterSpec, PacketFilterModel, matches_packet, parse_filter
from packet_model import PacketTableModel
from scapy.all import ARP, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, VXLAN
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6ND_NS


def ethernet():
    """构造带显式地址的 Ethernet 头，避免 Scapy 解析本机地址。"""
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


class FilterSpecTests(unittest.TestCase):
    """验证过滤输入的规范化和严格校验。"""

    def test_normalizes_protocol_case_host_and_cidr(self):
        spec = parse_filter(" tcp ", "192.0.2.37/24", "00443")
        self.assertEqual(spec, FilterSpec("TCP", ip_network("192.0.2.0/24"), 443))
        self.assertEqual(
            parse_filter(address="2001:0DB8:0000::1").network,
            ip_network("2001:db8::1/128"),
        )
        self.assertEqual(parse_filter(address="192.0.2.37/24").network, ip_network("192.0.2.0/24"))
        self.assertEqual(
            parse_filter(address="2001:db8::1234/64").network,
            ip_network("2001:db8::/64"),
        )
        self.assertEqual(parse_filter(port="0").port, 0)
        self.assertEqual(parse_filter(port="65535").port, 65535)
        self.assertEqual(parse_filter(address=" ", port=" "), FilterSpec())

    def test_rejects_invalid_inputs(self):
        invalid = [
            {"protocol": "TLS"},
            {"protocol": ""},
            {"address": "not-an-ip"},
            {"address": "192.0.2.1/33"},
            {"address": "2001:db8::/129"},
            {"address": "192.0.2.1,192.0.2.2"},
            {"port": "-1"},
            {"port": "65536"},
            {"port": "443.0"},
            {"port": "+443"},
            {"port": "80 or 443"},
            {"port": "４４３"},
        ]
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                parse_filter(**values)


class MatchesPacketTests(unittest.TestCase):
    """验证协议、地址、端口和应用层识别的组合语义。"""

    def test_source_or_destination_ipv4_and_ipv6_and_ports(self):
        pairs = [
            ("192.0.2.1", "198.51.100.5", IP),
            ("2001:db8::1", "2001:db8:1::5", IPv6),
        ]
        for source, destination, network in pairs:
            packet = ethernet() / network(src=source, dst=destination) / TCP(sport=50000, dport=443)
            for address in (source, destination):
                with self.subTest(address=address):
                    self.assertTrue(matches_packet(packet, parse_filter(address=address)))
            for port in ("50000", "443"):
                self.assertTrue(matches_packet(packet, parse_filter(port=port)))
            self.assertFalse(matches_packet(packet, parse_filter(port="80")))

    def test_cidr_family_and_boundary(self):
        packet = ethernet() / IP(src="192.0.2.255", dst="198.51.100.1") / UDP(sport=53, dport=12345)
        self.assertTrue(matches_packet(packet, parse_filter(address="192.0.2.0/24")))
        self.assertFalse(matches_packet(packet, parse_filter(address="192.0.3.0/24")))
        self.assertFalse(matches_packet(packet, parse_filter(address="::/0")))
        ipv6 = ethernet() / IPv6(src="2001:db8:1::1", dst="2001:db8:2::2") / TCP()
        self.assertTrue(matches_packet(ipv6, parse_filter(address="2001:db8:1::/48")))
        self.assertFalse(matches_packet(ipv6, parse_filter(address="2001:db8:3::/48")))
        self.assertFalse(matches_packet(ipv6, parse_filter(address="0.0.0.0/0")))

    def test_conditions_are_anded_across_protocol_address_and_port(self):
        packet = ethernet() / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=60000, dport=443)
        self.assertTrue(matches_packet(packet, parse_filter("TCP", "192.0.2.0/24", "443")))
        for values in [
            ("UDP", "192.0.2.0/24", "443"),
            ("TCP", "203.0.113.0/24", "443"),
            ("TCP", "192.0.2.0/24", "80"),
        ]:
            with self.subTest(values=values):
                self.assertFalse(matches_packet(packet, parse_filter(*values)))

    def test_protocol_layers_include_tcp_udp_ip_icmp_and_icmpv6(self):
        ipv4_tcp = ethernet() / IP() / TCP()
        ipv4_udp = ethernet() / IP() / UDP()
        ipv4_icmp = ethernet() / IP() / ICMP()
        self.assertTrue(matches_packet(ipv4_tcp, parse_filter("TCP")))
        self.assertTrue(matches_packet(ipv4_udp, parse_filter("UDP")))
        self.assertTrue(matches_packet(ipv4_icmp, parse_filter("ICMP")))
        self.assertTrue(matches_packet(ipv4_tcp, parse_filter("IPv4")))
        self.assertFalse(matches_packet(ipv4_tcp, parse_filter("IPv6")))

        for message in (ICMPv6EchoRequest(), ICMPv6ND_NS(tgt="2001:db8::2")):
            packet = ethernet() / IPv6(src="2001:db8::1", dst="2001:db8::2") / message
            self.assertTrue(matches_packet(packet, parse_filter("ICMPv6")))
            self.assertTrue(matches_packet(packet, parse_filter("IPv6")))
            self.assertFalse(matches_packet(packet, parse_filter("ICMP")))
            self.assertFalse(matches_packet(packet, parse_filter(port="0")))

    def test_arp_matches_only_unconstrained_filter(self):
        packet = ethernet() / ARP(psrc="192.0.2.1", pdst="192.0.2.2")
        self.assertTrue(matches_packet(packet, parse_filter()))
        for values in (
            {"protocol": "IPv4"},
            {"protocol": "TCP"},
            {"address": "192.0.2.1"},
            {"port": "80"},
        ):
            with self.subTest(values=values):
                self.assertFalse(matches_packet(packet, parse_filter(**values)))

    def test_http_request_response_and_nonstandard_port_require_complete_crlf(self):
        lines = [
            b"GET / HTTP/1.1\r\n",
            b"POST /submit?x=1 HTTP/1.0\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"HTTP/1.0 404 Not Found\r\n",
        ]
        for line in lines:
            with self.subTest(line=line):
                packet = ethernet() / IP() / TCP(dport=8080) / Raw(line + b"Host: example.test\r\n\r\n")
                self.assertTrue(matches_packet(packet, parse_filter("HTTP")))
                reparsed = ethernet() / IP(bytes(packet)[14:])
                self.assertTrue(matches_packet(reparsed, parse_filter("HTTP")))

    def test_http_rejects_tls_incomplete_udp_and_cross_tunnel_payloads(self):
        payloads = [
            b"",
            b"GET / HTTP/1.1",
            b"GET / HTTP/1.1\n",
            b"GET / HT",
            b"GET / HTTP/2.0\r\n",
            b"HTTP/1.1 OK\r\n",
            b"noise GET / HTTP/1.1\r\n",
            b"\x16\x03\x01\x00\x10TLS data",
            b"x" * 8192 + b"GET / HTTP/1.1\r\n",
        ]
        for payload in payloads:
            with self.subTest(payload=payload[:30]):
                packet = ethernet() / IP() / TCP(dport=80) / Raw(payload)
                self.assertFalse(matches_packet(packet, parse_filter("HTTP")))
        self.assertFalse(
            matches_packet(
                ethernet() / IP() / UDP(dport=80) / Raw(b"GET / HTTP/1.1\r\n"),
                parse_filter("HTTP"),
            )
        )
        tunneled = (
            ethernet()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=4789, dport=4789)
            / VXLAN()
            / IP(src="198.51.100.1", dst="198.51.100.2")
            / TCP(sport=1234, dport=8080)
            / Raw(b"GET / HTTP/1.1\r\n")
        )
        self.assertFalse(matches_packet(tunneled, parse_filter("HTTP")))

    def test_nested_vxlan_uses_outer_udp_for_protocol_address_and_port(self):
        tunneled = (
            ethernet()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=4789, dport=4789)
            / VXLAN()
            / IP(src="198.51.100.1", dst="198.51.100.2")
            / TCP(sport=1234, dport=8080)
        )
        self.assertTrue(matches_packet(tunneled, parse_filter("UDP")))
        self.assertTrue(matches_packet(tunneled, parse_filter(port="4789")))
        self.assertFalse(matches_packet(tunneled, parse_filter("TCP")))
        self.assertFalse(matches_packet(tunneled, parse_filter(port="1234")))
        self.assertFalse(matches_packet(tunneled, parse_filter(address="198.51.100.1")))


class PacketFilterModelTests(unittest.TestCase):
    """验证过滤代理的源行映射、追加、空结果和重置。"""

    @classmethod
    def setUpClass(cls):
        cls.application = app()

    def test_filter_maps_original_rows_and_keeps_source_order(self):
        source = PacketTableModel()
        packets = [
            ethernet() / IP() / UDP(dport=53),
            ethernet() / IP(dst="192.0.2.2") / TCP(dport=443),
            ethernet() / IPv6() / TCP(dport=80),
        ]
        source.append_batch(packets)
        proxy = PacketFilterModel()
        proxy.setSourceModel(source)
        proxy.set_filter(parse_filter("TCP", port="443"))
        self.assertEqual(proxy.rowCount(), 1)
        self.assertEqual(proxy.mapToSource(proxy.index(0, 0)).row(), 1)
        self.assertEqual(proxy.data(proxy.index(0, 0)), "2")
        self.assertEqual(source.packets, packets)

        source.append_batch([ethernet() / IP() / TCP(sport=443, dport=60000)])
        self.assertEqual(proxy.rowCount(), 2)
        self.assertEqual(proxy.mapToSource(proxy.index(1, 0)).row(), 3)
        self.assertEqual(proxy.data(proxy.index(1, 0)), "4")

    def test_empty_result_reset_clear_and_append_keep_source_row_numbers(self):
        source = PacketTableModel()
        source.append_batch([
            ethernet() / IP() / TCP(dport=80),
            ethernet() / IP() / UDP(dport=53),
        ])
        proxy = PacketFilterModel()
        proxy.setSourceModel(source)
        proxy.set_filter(parse_filter("TCP", port="443"))
        self.assertEqual(proxy.rowCount(), 0)
        proxy.set_filter(parse_filter())
        self.assertEqual(proxy.rowCount(), 2)
        self.assertEqual(proxy.data(proxy.index(0, 0)), "1")
        self.assertEqual(proxy.data(proxy.index(1, 0)), "2")

        source.clear()
        self.assertEqual(source.rowCount(), 0)
        self.assertEqual(proxy.rowCount(), 0)
        source.append_batch([ethernet() / IP() / TCP(dport=443)])
        self.assertEqual(proxy.rowCount(), 1)
        self.assertEqual(proxy.mapToSource(proxy.index(0, 0)).row(), 0)
        self.assertEqual(proxy.data(proxy.index(0, 0)), "1")


if __name__ == "__main__":
    unittest.main()
