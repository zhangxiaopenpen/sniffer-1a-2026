"""TCP 提取与首条应用消息解析的边界、截断及歧义回归测试。"""

import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop,
)
from scapy.layers.l2 import Dot1Q, Ether, Loopback
from scapy.packet import Raw

from examples.make_stream_demo import make_client_hello
from tcp_application import parse_stream_payload
from tcp_transport import extract_tcp_segment


DOMAIN = "www.parser.example.test"
REQUEST = f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n".encode("ascii")


def _ipv4(payload=REQUEST):
    """创建固定端点、完整头部的原始 IPv4/TCP 包。"""
    return IP(bytes(IP(src="192.0.2.10", dst="198.51.100.20")
                    / TCP(sport=50100, dport=80, seq=1001, ack=9001, flags="PA")
                    / Raw(payload)))


def _record(content, kind=22):
    """用正确声明长度封装一个 TLS record。"""
    return bytes((kind, 3, 3)) + len(content).to_bytes(2, "big") + content


def _extension(kind, value):
    """封装 TLS 扩展，供长度损坏测试逐层构造。"""
    return kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _names(*names):
    """构造一个或多个同类型 host_name 条目。"""
    entries = b"".join(b"\x00" + len(name).to_bytes(2, "big") + name for name in names)
    return len(entries).to_bytes(2, "big") + entries


def _hello(extensions=b"", *, body=None):
    """构造 ClientHello，可用原始 body 覆盖固定头和向量。"""
    if body is None:
        body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00"
                + len(extensions).to_bytes(2, "big") + extensions)
    return _record(b"\x01" + len(body).to_bytes(3, "big") + body)


class TcpTransportTests(unittest.TestCase):
    """声明长度、外层边界和不可变原包约束。"""

    def test_ipv4_fields_and_source_index(self):
        packet = _ipv4()
        packet.time = 123.25
        segment = extract_tcp_segment(packet, 17)
        self.assertEqual(segment.payload, REQUEST)
        self.assertEqual(segment.sequence, 1001)
        self.assertEqual(segment.acknowledgement, 9001)
        self.assertEqual(segment.flags, frozenset("PA"))
        self.assertEqual(segment.source_packet_index, 17)
        self.assertEqual(segment.timestamp, 123.25)
        source, destination = segment.flow_key.endpoints_for(segment.direction)
        self.assertEqual((source.address, source.port), ("192.0.2.10", 50100))
        self.assertEqual((destination.address, destination.port), ("198.51.100.20", 80))

    def test_ipv6_with_regular_extensions(self):
        packet = IPv6(bytes(IPv6(src="2001:db8::10", dst="2001:db8::20")
                            / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt()
                            / TCP(sport=50200, dport=443, flags="S", seq=0xffffffff)
                            / Raw(b"hello")))
        segment = extract_tcp_segment(packet, 4)
        self.assertEqual(segment.payload, b"hello")
        self.assertEqual(segment.sequence, 0xffffffff)
        self.assertEqual(segment.flow_key.endpoint_a.ip_version, 6)

    def test_vlan_and_loopback_link_headers(self):
        for packet in (Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
                       / Dot1Q(vlan=7) / _ipv4(), Loopback(type=2) / _ipv4()):
            with self.subTest(packet=packet.summary()):
                self.assertEqual(extract_tcp_segment(packet, 0).payload, REQUEST)

    def test_padding_excluded_and_original_packet_unchanged(self):
        frame = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20") / _ipv4()
        packet = Ether(bytes(frame) + b"Host: fake.example.test\r\n\r\n")
        original, before = packet.original, bytes(packet)
        fields = packet.show(dump=True)
        self.assertEqual(extract_tcp_segment(packet, 0).payload, REQUEST)
        self.assertEqual(packet.original, original)
        self.assertEqual(bytes(packet), before)
        self.assertEqual(packet.show(dump=True), fields)

    def test_ipv4_first_and_later_fragments_rejected(self):
        for flags, offset in (("MF", 0), (0, 1)):
            raw = bytearray(bytes(_ipv4()))
            raw[6:8] = ((0x2000 if flags else 0) | offset).to_bytes(2, "big")
            with self.subTest(flags=flags, offset=offset), self.assertRaisesRegex(ValueError, "分片"):
                extract_tcp_segment(IP(bytes(raw)), 0)

    def test_ipv6_fragment_and_atomic_fragment_rejected(self):
        for offset, more in ((0, 1), (1, 0), (0, 0)):
            packet = IPv6(bytes(IPv6(src="2001:db8::10", dst="2001:db8::20")
                                / IPv6ExtHdrFragment(offset=offset, m=more)
                                / TCP(sport=50100, dport=80) / Raw(REQUEST)))
            with self.subTest(offset=offset, more=more), self.assertRaisesRegex(ValueError, "分片"):
                extract_tcp_segment(packet, 0)

    def test_ipv4_declared_total_exceeding_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, "截断"):
            extract_tcp_segment(IP(bytes(_ipv4())[:-3]), 0)

    def test_ipv4_header_and_tcp_header_lengths_rejected(self):
        original = bytes(_ipv4())
        for label, offset, value in (("short IHL", 0, 0x44), ("short TCP", 32, 0x40),
                                     ("long TCP", 32, 0xf0)):
            raw = bytearray(original[:40] if label == "long TCP" else original)
            raw[offset] = value
            raw[2:4] = len(raw).to_bytes(2, "big")
            with self.subTest(label=label), self.assertRaises(ValueError):
                extract_tcp_segment(IP(bytes(raw)), 0)
        raw = bytearray(original[:30])
        raw[2:4] = len(raw).to_bytes(2, "big")
        with self.assertRaisesRegex(ValueError, "TCP 头部"):
            extract_tcp_segment(IP(bytes(raw)), 0)

    def test_ipv6_payload_and_extension_lengths_rejected(self):
        packet = IPv6(src="2001:db8::10", dst="2001:db8::20") / IPv6ExtHdrHopByHop()
        raw = bytes(packet / TCP(sport=50100, dport=443) / Raw(b"data"))
        with self.assertRaisesRegex(ValueError, "截断"):
            extract_tcp_segment(IPv6(raw[:-1]), 0)
        mutated = bytearray(raw)
        mutated[41] = 255
        with self.assertRaisesRegex(ValueError, "扩展头"):
            extract_tcp_segment(IPv6(bytes(mutated)), 0)

    def test_icmp_quoted_tcp_and_ip_tunnels_not_followed(self):
        packets = (
            IP(src="192.0.2.1", dst="192.0.2.2") / ICMP(type=3) / _ipv4(),
            IP(src="192.0.2.1", dst="192.0.2.2") / _ipv4(),
            IPv6(src="2001:db8::1", dst="2001:db8::2") / _ipv4(),
            IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=12, dport=34) / Raw(bytes(_ipv4())),
            Raw(bytes(_ipv4())),
        )
        for packet in packets:
            with self.subTest(packet=packet.summary()):
                self.assertIsNone(extract_tcp_segment(packet, 0))


class TcpApplicationTests(unittest.TestCase):
    """消息层长度和唯一证据约束。"""

    def assertNoEvidence(self, payload):
        """要求畸形消息无证据，并返回结果供其他状态断言。"""
        result = parse_stream_payload(payload)
        self.assertEqual(result.evidence, ())
        return result

    def test_http_host_and_valid_port(self):
        for host in (DOMAIN, DOMAIN.upper() + ":8080", DOMAIN + "."):
            with self.subTest(host=host):
                result = parse_stream_payload(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                self.assertEqual(result.protocol, "HTTP")
                self.assertEqual(result.evidence[0].domain, DOMAIN)
                self.assertEqual(result.evidence[0].source, "HTTP Host")

    def test_duplicate_missing_invalid_http_fields(self):
        bad_headers = (
            b"Host: a.example.test\r\nHost: b.example.test",
            b"host: a.example.test\r\nHOST: a.example.test",
            b"Accept: */*", b"Host: 192.0.2.1", b"Host: a.example.test:70000",
            b"Host: [2001:db8::1]", b"Host: a.example.test\r\n invalid-fold",
            b"Host: a.example.test\r\nBad Header: value",
            b"Host: a.example.test\r\nMissingColon",
            b"Host: a.example.test\r\nX-Test: value\x00hidden",
        )
        for header in bad_headers:
            with self.subTest(header=header):
                self.assertNoEvidence(b"GET / HTTP/1.1\r\n" + header + b"\r\n\r\n")

    def test_incomplete_http_and_header_budgets(self):
        for data in (
            REQUEST[:-1], b"GET / HTTP/1.1\r\nHost: partial",
            b"GET / HTTP/1.1\r\nX-Large: " + b"a" * 16384 + b"\r\nHost: " + DOMAIN.encode() + b"\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: " + DOMAIN.encode() + b"\r\n" + b"X-A: b\r\n" * 128 + b"\r\n",
        ):
            with self.subTest(length=len(data)):
                self.assertNoEvidence(data)

    def test_response_unknown_and_leading_junk_not_scanned(self):
        self.assertNoEvidence(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        self.assertNoEvidence(b"HTTP/1.1 200 OK\r\nHost: " + DOMAIN.encode() + b"\r\n\r\n")
        self.assertNoEvidence(b"unknown-prefix\x00" + REQUEST)
        self.assertNoEvidence(b"")

    def test_tls_clienthello_split_across_records(self):
        handshake = make_client_hello(DOMAIN)[5:]
        split = len(handshake) - 9
        payload = _record(handshake[:3]) + _record(handshake[3:split]) + _record(handshake[split:])
        result = parse_stream_payload(payload)
        self.assertEqual(result.protocol, "TLS")
        self.assertEqual(result.evidence[0].domain, DOMAIN)
        self.assertEqual(result.evidence[0].source, "TLS SNI")

    def test_tls_record_and_handshake_declared_lengths(self):
        good = make_client_hello(DOMAIN)
        too_long = bytearray(good)
        too_long[3:5] = (len(good)).to_bytes(2, "big")
        handshake_long = bytearray(good)
        handshake_long[6:9] = (len(good)).to_bytes(3, "big")
        for data in (good[:3], good[:-1], bytes(too_long), bytes(handshake_long),
                     b"\x16\x03\x03\xff\xff" + bytes(65535),
                     _record(b"\x01\x01\x00\x01")):
            with self.subTest(length=len(data)):
                self.assertNoEvidence(data)

    def test_clienthello_vectors_and_extensions_must_be_complete(self):
        body = bytearray(make_client_hello(DOMAIN)[9:])
        for label, offset, value in (("session", 34, 255), ("suites", 36, 3),
                                     ("compression", 39, 0), ("extension total", 42, 0)):
            mutated = bytearray(body)
            mutated[offset] = value
            with self.subTest(label=label):
                self.assertNoEvidence(_hello(body=bytes(mutated)))
        self.assertNoEvidence(_hello(body=bytes(body[:34])))
        extension = _extension(0, _names(DOMAIN.encode()))
        self.assertNoEvidence(_hello(extension[:-1]))
        self.assertNoEvidence(_hello(extension + b"\x00"))

    def test_duplicate_tls_extensions_or_host_names_rejected(self):
        sni = _extension(0, _names(DOMAIN.encode()))
        for extensions in (sni + sni, sni + _extension(10, b"") + _extension(10, b""),
                           _extension(0, _names(DOMAIN.encode(), b"other.example.test"))):
            with self.subTest(length=len(extensions)):
                self.assertNoEvidence(_hello(extensions))

    def test_sni_inner_length_and_invalid_names_rejected(self):
        valid = bytearray(_names(DOMAIN.encode()))
        bad_list = bytearray(valid)
        bad_list[1] += 1
        bad_name = bytearray(valid)
        bad_name[4] += 1
        for names in (bytes(bad_list), bytes(bad_name), _names(b""),
                      _names(b" bad.example.test"), _names(b"192.0.2.1"),
                      _names(b"bad\x00.example.test")):
            with self.subTest(names=names):
                self.assertNoEvidence(_hello(_extension(0, names)))

    def test_ech_only_labels_visible_outer_name(self):
        result = parse_stream_payload(_hello(
            _extension(0, _names(DOMAIN.encode())) + _extension(0xfe0d, b"\x00")))
        self.assertEqual(result.evidence[0].domain, DOMAIN)
        self.assertIn("外层 SNI", result.evidence[0].detail)
        self.assertIn("不能确认真实目标", result.note)

    def test_tls_no_sni_encryption_interruption_and_record_budget(self):
        self.assertNoEvidence(_hello())
        self.assertNoEvidence(_record(b"encrypted", kind=23))
        handshake = make_client_hello(DOMAIN)[5:]
        self.assertNoEvidence(_record(handshake[:10]) + _record(b"\x01", kind=20)
                              + _record(handshake[10:]))
        self.assertNoEvidence(_record(b"") * 16 + make_client_hello(DOMAIN))

    def test_complete_first_message_survives_large_trailing_data(self):
        tail = b"x" * (128 * 1024)
        for data, source in ((REQUEST + tail, "HTTP Host"),
                             (make_client_hello(DOMAIN) + tail, "TLS SNI")):
            with self.subTest(source=source):
                result = parse_stream_payload(data)
                self.assertEqual(result.evidence[0].domain, DOMAIN)
                self.assertEqual(result.evidence[0].source, source)


if __name__ == "__main__":
    unittest.main()
