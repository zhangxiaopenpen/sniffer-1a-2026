"""阶段 4 的有界单包域名证据解析器。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _IPv6ExtHdr
from scapy.layers.l2 import ARP

from domain_models import DNSAnswer, DNSMessage, DNSQuestion, DomainEvidence, EvidenceSource

MAX_PAYLOAD = 64 * 1024
MAX_HTTP_HEADERS = 16 * 1024
MAX_DNS_RECORDS = 64
MAX_DNS_QUESTIONS = 16
MAX_TLS_RECORDS = 16
MAX_TLS_SNI_NAMES = 16
_TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_HTTP_REQUEST = re.compile(_TOKEN + rb" [^\x00-\x20\x7f]+ HTTP/1\.[01]")
_HTTP_RESPONSE = re.compile(rb"HTTP/1\.[01] [0-9]{3}(?:[ \t\x20-\x7e\x80-\xff]*)")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


@dataclass(frozen=True)
class PacketParseResult:
    """单个原始包的直接域名证据和 DNS 元数据。"""

    protocol: str = ""
    evidence: tuple[DomainEvidence, ...] = ()
    dns_message: DNSMessage | None = None
    note: str = ""


def normalize_domain(value: str | bytes) -> str:
    """规范化并验证纯域名，不接受 URL、IP 或通配符。"""
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if not isinstance(value, str):
        raise ValueError("域名必须是字符串")
    text = value.strip()
    if text.endswith("."):
        text = text[:-1]
    if not text or len(text) > 253 or any(char in text for char in "/\\:@?#[]*%"):
        raise ValueError("域名格式不合法")
    try:
        text = text.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("域名 IDNA 编码不合法") from exc
    if not all(_LABEL.fullmatch(label) for label in text.split(".")):
        raise ValueError("域名标签格式不合法")
    try:
        ip_address(text)
    except ValueError:
        return text
    raise ValueError("IP 地址不作为域名证据")


def _outer_layers(packet):
    network = packet
    while network is not None and not isinstance(network, (IP, IPv6, ARP)):
        network = getattr(network, "payload", None)
    if network is None or isinstance(network, ARP):
        return None, None
    transport = getattr(network, "payload", None)
    if isinstance(network, IPv6):
        while isinstance(transport, _IPv6ExtHdr):
            transport = getattr(transport, "payload", None)
    if isinstance(network, IP) and int(getattr(network, "frag", 0) or 0):
        return network, None
    return network, transport


def _payload_bytes(transport) -> bytes:
    payload = getattr(transport, "payload", None)
    if payload is None:
        return b""
    original = getattr(payload, "original", None)
    if isinstance(original, (bytes, bytearray, memoryview)) and original:
        return bytes(original)[:MAX_PAYLOAD]
    try:
        return bytes(payload)[:MAX_PAYLOAD]
    except Exception:
        return b""


def _endpoint(network, transport):
    source = str(getattr(network, "src", ""))
    destination = str(getattr(network, "dst", ""))
    return source, destination, int(getattr(transport, "sport", 0)), int(getattr(transport, "dport", 0))


def _dns_rr_chain(record):
    while isinstance(record, DNSRR):
        yield record
        record = record.payload


def _rr_value(record) -> str | None:
    rtype = int(getattr(record, "type", 0))
    value = getattr(record, "rdata", None)
    if rtype in (1, 28):
        try:
            return str(ip_address(value))
        except (ValueError, TypeError):
            return None
    if rtype == 5:
        try:
            return normalize_domain(value)
        except (ValueError, TypeError, UnicodeError):
            return None
    return None


def _parse_dns(data: bytes, network, transport, packet_index: int, timestamp) -> PacketParseResult:
    is_tcp = isinstance(transport, TCP)
    if is_tcp:
        if len(data) < 2:
            raise ValueError("DNS/TCP 长度前缀不完整")
        declared = int.from_bytes(data[:2], "big")
        if declared != len(data) - 2:
            raise ValueError("DNS/TCP 不是单个完整消息，未跨 TCP 分段重组")
        data = data[2:]
    if len(data) < 12 or len(data) > MAX_PAYLOAD:
        raise ValueError("DNS 消息长度不合法")
    message = DNS(data)
    qd = int(message.qdcount or 0)
    an = int(message.ancount or 0)
    ns = int(message.nscount or 0)
    ar = int(message.arcount or 0)
    if qd > MAX_DNS_QUESTIONS or an + ns + ar > MAX_DNS_RECORDS:
        raise ValueError("DNS 问题或资源记录数量超限")
    source, destination, sport, dport = _endpoint(network, transport)
    questions: list[DNSQuestion] = []
    evidence: list[DomainEvidence] = []
    question_items = list(message.qd) if message.qd is not None else []
    for question in question_items[:qd]:
        if not isinstance(question, DNSQR):
            raise ValueError("DNS 问题区不完整")
        name = normalize_domain(question.qname)
        qtype = int(question.qtype)
        qclass = int(question.qclass)
        questions.append(DNSQuestion(name, qtype, qclass))
        evidence.append(DomainEvidence(
            name,
            EvidenceSource.DNS_RESPONSE if bool(message.qr) else EvidenceSource.DNS_QUERY,
            packet_index,
            "DNS 应答问题名" if message.qr else "DNS 查询问题名",
            transaction_id=int(message.id), qname=name, qtype=qtype,
        ))
    answers: list[DNSAnswer] = []
    for section, count, records in (
        ("answer", an, message.an),
        ("authority", ns, message.ns),
        ("additional", ar, message.ar),
    ):
        for item in list(records)[:count] if records is not None else ():
            rtype = int(getattr(item, "type", 0))
            value = _rr_value(item)
            if value is None or rtype not in (1, 5, 28):
                continue
            try:
                name = normalize_domain(item.rrname)
            except (ValueError, TypeError, UnicodeError):
                continue
            ttl = max(0, int(getattr(item, "ttl", 0) or 0))
            answers.append(DNSAnswer(name, rtype, value, ttl, section))
            if bool(message.qr):
                evidence.append(DomainEvidence(
                    name, EvidenceSource.DNS_RESPONSE, packet_index,
                    f"DNS {('A' if rtype == 1 else 'AAAA' if rtype == 28 else 'CNAME')} 记录",
                    transaction_id=int(message.id), qname=questions[0].qname if questions else name,
                    qtype=questions[0].qtype if questions else None, answers=(value,), ttl=ttl,
                ))
    protocol = "DNS"
    dns = DNSMessage(
        transaction_id=int(message.id), is_response=bool(message.qr),
        questions=tuple(questions), answers=tuple(answers), source_ip=source,
        destination_ip=destination, source_port=sport, destination_port=dport,
        transport="TCP" if is_tcp else "UDP", truncated=bool(int(message.tc or 0)),
        rcode=int(message.rcode or 0), packet_index=packet_index, timestamp=timestamp,
    )
    return PacketParseResult(protocol, tuple(dict.fromkeys(evidence)), dns,
                             "DNS 响应被截断或返回错误" if dns.truncated or dns.rcode else "")


def _rr_chain_limited(record, count):
    for _ in range(count):
        if not isinstance(record, DNSRR):
            raise ValueError("DNS 资源记录区不完整")
        yield record
        record = record.payload


def _parse_http(data: bytes, packet_index: int) -> PacketParseResult | None:
    if len(data) > MAX_HTTP_HEADERS:
        data = data[:MAX_HTTP_HEADERS]
    end = data.find(b"\r\n")
    if end < 0:
        return None
    first = data[:end]
    if not (_HTTP_REQUEST.fullmatch(first) or _HTTP_RESPONSE.fullmatch(first)):
        return None
    header_end = data.find(b"\r\n\r\n", end + 2)
    if header_end < 0:
        return PacketParseResult("HTTP", note="HTTP 头部不完整，未跨 TCP 分段重组")
    if _HTTP_RESPONSE.fullmatch(first):
        return PacketParseResult("HTTP", note="HTTP 响应本身不包含可确定请求域名的 Host")
    hosts = []
    for line in data[end + 2:header_end].split(b"\r\n"):
        key, sep, value = line.partition(b":")
        if not sep:
            continue
        if key.lower() == b"host":
            hosts.append(value.strip())
    if len(hosts) != 1:
        return PacketParseResult("HTTP", note="Host 缺失或重复，未猜测域名")
    authority = hosts[0].decode("ascii")
    if authority.count(":") == 1:
        authority, port = authority.rsplit(":", 1)
        if not port.isdigit() or int(port) > 65535:
            return PacketParseResult("HTTP", note="Host 端口不合法")
    try:
        domain = normalize_domain(authority)
    except (ValueError, UnicodeError):
        return PacketParseResult("HTTP", note="Host 不是合法纯域名")
    return PacketParseResult("HTTP", (DomainEvidence(
        domain, EvidenceSource.HTTP_HOST, packet_index, "同一 TCP 包内完整 HTTP Host",
    ),))


def _parse_tls(data: bytes, packet_index: int) -> PacketParseResult | None:
    if len(data) < 5 or data[0] != 22 or data[1] != 3 or data[2] > 4:
        return None
    cursor = 0
    for _ in range(MAX_TLS_RECORDS):
        if cursor + 5 > len(data):
            return PacketParseResult("TLS", note="TLS 记录头不完整，未跨 TCP 分段重组")
        kind, major, minor = data[cursor], data[cursor + 1], data[cursor + 2]
        length = int.from_bytes(data[cursor + 3:cursor + 5], "big")
        end = cursor + 5 + length
        if kind != 22 or major != 3 or minor > 4 or end > len(data):
            return PacketParseResult("TLS", note="TLS ClientHello 记录不完整，未跨 TCP 分段重组")
        body = data[cursor + 5:end]
        if len(body) >= 4 and body[0] == 1:
            handshake_len = int.from_bytes(body[1:4], "big")
            if handshake_len + 4 > len(body):
                return PacketParseResult("TLS", note="TLS ClientHello 不完整，未跨 TCP 分段重组")
            hello = body[4:4 + handshake_len]
            domain = _extract_sni(hello)
            if domain:
                return PacketParseResult("TLS", (DomainEvidence(
                    domain, EvidenceSource.TLS_SNI, packet_index,
                    "同一 TCP 包内完整 TLS ClientHello SNI",
                ),))
        cursor = end
        if cursor == len(data):
            break
    return PacketParseResult("TLS", note="未见可解析的明文 SNI")


def _extract_sni(body: bytes) -> str | None:
    if len(body) < 34:
        return None
    session_length = body[34]
    cursor = 35 + session_length
    if cursor + 2 > len(body):
        return None
    suites_length = int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 2 + suites_length
    if cursor >= len(body):
        return None
    compression_length = body[cursor]
    cursor += 1 + compression_length
    if cursor + 2 > len(body):
        return None
    extensions_length = int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 2
    end = cursor + extensions_length
    if end != len(body):
        return None
    while cursor + 4 <= end:
        kind = int.from_bytes(body[cursor:cursor + 2], "big")
        length = int.from_bytes(body[cursor + 2:cursor + 4], "big")
        cursor += 4
        extension_end = cursor + length
        if extension_end > end:
            return None
        if kind == 0:
            if length < 5:
                return None
            list_length = int.from_bytes(body[cursor:cursor + 2], "big")
            position = cursor + 2
            list_end = position + list_length
            if list_end != extension_end:
                return None
            names = []
            while position + 3 <= list_end and len(names) < MAX_TLS_SNI_NAMES:
                name_type = body[position]
                name_length = int.from_bytes(body[position + 1:position + 3], "big")
                position += 3
                if position + name_length > list_end:
                    return None
                if name_type == 0:
                    try:
                        names.append(normalize_domain(body[position:position + name_length]))
                    except (ValueError, UnicodeError):
                        return None
                position += name_length
            return names[0] if len(names) == 1 and position == list_end else None
        cursor = extension_end
    return None


def analyze_packet(packet, packet_index: int = 0) -> PacketParseResult:
    """解析一个包内的 DNS、HTTP Host 或 TLS SNI 直接证据。"""
    transport = None
    try:
        network, transport = _outer_layers(packet)
        if network is None or not isinstance(transport, (TCP, UDP)):
            return PacketParseResult()
        data = _payload_bytes(transport)
        if not data:
            return PacketParseResult()
        try:
            timestamp = float(packet.time)
        except (AttributeError, TypeError, ValueError, OverflowError):
            timestamp = None
        if DNS in packet or 53 in (int(transport.sport), int(transport.dport)):
            return _parse_dns(data, network, transport, packet_index, timestamp)
        if isinstance(transport, TCP):
            http = _parse_http(data, packet_index)
            if http is not None:
                return http
            tls = _parse_tls(data, packet_index)
            if tls is not None:
                return tls
    except Exception as exc:
        return PacketParseResult("DNS" if 53 in (int(getattr(transport, "sport", 0)), int(getattr(transport, "dport", 0))) else "", note=str(exc))
    return PacketParseResult()
