"""解析可靠 TCP 连续载荷起点的 HTTP Host 和 TLS ClientHello SNI。"""

from __future__ import annotations

import re
from dataclasses import dataclass

from domain_parsers import normalize_domain

MAX_HTTP_HEADER_BYTES = 16 * 1024
MAX_HTTP_FIELDS = 128
MAX_TLS_RECORDS = 16
MAX_TLS_MESSAGES = 16
MAX_TLS_HANDSHAKE_BYTES = 64 * 1024
MAX_TLS_RECORD_BYTES = 18432
MAX_TLS_EXTENSIONS = 128
MAX_TLS_NAMES = 16
_TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_REQUEST = re.compile(_TOKEN + rb" [^\x00-\x20\x7f]+ HTTP/1\.[01]")
_RESPONSE = re.compile(rb"HTTP/1\.[01] [0-9]{3}(?: [\t\x20-\x7e\x80-\xff]*)?")
_FIELD_NAME = re.compile(_TOKEN)
_FIELD_VALUE = re.compile(rb"[\t\x20-\x7e\x80-\xff]*")


@dataclass(frozen=True)
class ApplicationEvidence:
    """从完整首条应用消息中读取的域名及字段来源。"""

    domain: str
    source: str
    detail: str


@dataclass(frozen=True)
class StreamPayloadInfo:
    """应用协议识别结果，不代表解密内容或网站归属判定。"""

    protocol: str = ""
    evidence: tuple[ApplicationEvidence, ...] = ()
    note: str = ""


class _Malformed(ValueError):
    """消息长度、语法或字段存在歧义，不能发布域名证据。"""


def _wire_domain(value: bytes) -> str:
    """验证线上纯域名，拒绝被规范化函数掩盖的首尾空白。

    Args:
        value: 报文字段中的 ASCII 或 IDNA 字节。

    Returns:
        规范化的域名。
    """
    if not value or value != value.strip():
        raise _Malformed("域名字段为空或包含首尾空白")
    return normalize_domain(value)


def _http(payload: bytes) -> StreamPayloadInfo | None:
    """从完整 HTTP/1 头部读取唯一 Host，响应不产生 Host 证据。"""
    header = payload[:MAX_HTTP_HEADER_BYTES]
    first_end = header.find(b"\r\n")
    if first_end < 0:
        return None
    first = header[:first_end]
    request = bool(_REQUEST.fullmatch(first))
    if not request and not _RESPONSE.fullmatch(first):
        return None
    header_end = header.find(b"\r\n\r\n")
    if header_end < 0:
        return StreamPayloadInfo("HTTP", note="HTTP 头部不完整或超过 16 KiB")
    fields = header[first_end + 2:header_end].split(b"\r\n") if header_end > first_end else []
    if len(fields) > MAX_HTTP_FIELDS:
        raise _Malformed("HTTP 头字段数量超过 128")
    hosts = []
    for field in fields:
        key, separator, value = field.partition(b":")
        if not separator or not _FIELD_NAME.fullmatch(key) or not _FIELD_VALUE.fullmatch(value):
            raise _Malformed("HTTP 头字段语法不合法或包含折叠行")
        if key.lower() == b"host":
            hosts.append(value.strip(b" \t"))
    if not request:
        return StreamPayloadInfo("HTTP", note="HTTP 响应不提供请求的 Host 证据")
    if len(hosts) != 1:
        raise _Malformed("HTTP Host 缺失或重复，未猜测域名")
    authority = hosts[0]
    if b":" in authority:
        if authority.count(b":") != 1:
            raise _Malformed("HTTP Host 不是纯域名或含 IPv6 字面量")
        authority, port = authority.rsplit(b":", 1)
        if not re.fullmatch(rb"[0-9]{1,5}", port) or int(port) > 65535:
            raise _Malformed("HTTP Host 端口不合法")
    domain = _wire_domain(authority)
    return StreamPayloadInfo("HTTP", (ApplicationEvidence(
        domain, "HTTP Host", "TCP 连续载荷起点的完整 HTTP/1 请求头 Host 字段",
    ),))


def _server_names(data: bytes) -> str:
    """严格读取 server_name 扩展，拒绝重复名称类型和多 host_name。"""
    if len(data) < 2 or int.from_bytes(data[:2], "big") != len(data) - 2:
        raise _Malformed("TLS SNI 列表声明长度不符")
    position, names, kinds, count = 2, [], set(), 0
    while position < len(data):
        if position + 3 > len(data) or count >= MAX_TLS_NAMES:
            raise _Malformed("TLS SNI 条目头被截断或数量超过 16")
        kind = data[position]
        length = int.from_bytes(data[position + 1:position + 3], "big")
        position += 3
        if not length or position + length > len(data) or kind in kinds:
            raise _Malformed("TLS SNI 名称被截断、为空或名称类型重复")
        kinds.add(kind)
        if kind == 0:
            names.append(_wire_domain(data[position:position + length]))
        position += length
        count += 1
    if len(names) != 1:
        raise _Malformed("TLS SNI 未提供唯一 host_name")
    return names[0]


def _client_hello(body: bytes) -> tuple[str | None, bool]:
    """验证 ClientHello 的所有向量边界和扩展唯一性后返回 SNI/ECH。"""
    if len(body) < 35 or body[0] != 3 or body[1] > 4:
        raise _Malformed("TLS ClientHello 固定字段不完整或版本不支持")
    session_size = body[34]
    cursor = 35 + session_size
    if session_size > 32 or cursor + 2 > len(body):
        raise _Malformed("TLS session_id 长度不合法")
    suites_size = int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 2 + suites_size
    if suites_size < 2 or suites_size % 2 or cursor >= len(body):
        raise _Malformed("TLS cipher_suites 长度不合法")
    compression_size = body[cursor]
    cursor += 1 + compression_size
    if not compression_size or cursor > len(body):
        raise _Malformed("TLS compression_methods 长度不合法")
    if cursor == len(body):
        return None, False
    if cursor + 2 > len(body):
        raise _Malformed("TLS 扩展长度字段不完整")
    extension_size = int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 2
    if cursor + extension_size != len(body):
        raise _Malformed("TLS 扩展总长度与 ClientHello 不符")
    seen, domain, ech = set(), None, False
    while cursor < len(body):
        if cursor + 4 > len(body) or len(seen) >= MAX_TLS_EXTENSIONS:
            raise _Malformed("TLS 扩展头被截断或数量超过 128")
        kind = int.from_bytes(body[cursor:cursor + 2], "big")
        size = int.from_bytes(body[cursor + 2:cursor + 4], "big")
        cursor += 4
        end = cursor + size
        if end > len(body) or kind in seen:
            raise _Malformed("TLS 扩展被截断或重复")
        seen.add(kind)
        if kind == 0:
            domain = _server_names(body[cursor:end])
        if kind in (0xFE0D, 0xFFCE):
            ech = True
        cursor = end
    return domain, ech


def _tls(payload: bytes) -> StreamPayloadInfo:
    """在最多 16 条 TLS 记录内聚合握手，识别首个完整 ClientHello。"""
    cursor, message_count = 0, 0
    handshake = bytearray()
    for _ in range(MAX_TLS_RECORDS):
        if cursor + 5 > len(payload):
            raise _Malformed("TLS 记录头不完整")
        kind, major, minor = payload[cursor:cursor + 3]
        size = int.from_bytes(payload[cursor + 3:cursor + 5], "big")
        end = cursor + 5 + size
        if major != 3 or minor > 4 or kind not in (20, 21, 22, 23):
            raise _Malformed("TLS 记录类型或版本不合法")
        if size > MAX_TLS_RECORD_BYTES or end > len(payload):
            raise _Malformed("TLS 记录被截断或长度超限")
        if kind != 22:
            if handshake:
                raise _Malformed("TLS 未完成握手被其他记录打断")
            return StreamPayloadInfo("TLS", note="未见明文 ClientHello；不解析加密应用数据")
        handshake.extend(payload[cursor + 5:end])
        while len(handshake) >= 4:
            length = int.from_bytes(handshake[1:4], "big")
            if length > MAX_TLS_HANDSHAKE_BYTES or message_count >= MAX_TLS_MESSAGES:
                raise _Malformed("TLS 握手长度超过 64 KiB 或消息数量超过 16")
            if len(handshake) < 4 + length:
                break
            message_count += 1
            if handshake[0] == 1:
                domain, ech = _client_hello(bytes(handshake[4:4 + length]))
                if domain is None:
                    return StreamPayloadInfo("TLS", note="完整 ClientHello 中未见 SNI")
                detail = "TCP 连续载荷中的完整 TLS ClientHello 明文 SNI 字段"
                note = ""
                if ech:
                    detail += "（ECH 外层 SNI，不能确认真实目标域名）"
                    note = "检测到 ECH，仅显示外层 SNI，不能确认真实目标域名"
                return StreamPayloadInfo("TLS", (ApplicationEvidence(domain, "TLS SNI", detail),), note)
            del handshake[:4 + length]
        cursor = end
        if cursor == len(payload):
            if handshake:
                raise _Malformed("TLS 握手消息不完整")
            return StreamPayloadInfo("TLS", note="未见可解析的明文 ClientHello SNI")
    raise _Malformed("TLS 记录数超过 16，未继续解析")


def parse_stream_payload(payload: bytes) -> StreamPayloadInfo:
    """解析已由重组器确认可靠的连续载荷起点，不扫描未知偏移。

    Args:
        payload: 无缺口、无冲突、未截断且起点已确认的方向载荷。

    Returns:
        HTTP Host 或 TLS SNI 证据。畸形、不完整或不识别的数据仅返回说明。
        解析限于首个完整请求头或 ClientHello，不受后续大量应用数据影响。

    Raises:
        TypeError: 调用方未传入 bytes。
    """
    if not isinstance(payload, bytes):
        raise TypeError("TCP 连续载荷必须为 bytes")
    if not payload:
        return StreamPayloadInfo(note="没有应用载荷")
    protocol = "HTTP"
    try:
        http = _http(payload)
        if http is not None:
            return http
        if payload[0] in (20, 21, 22, 23) and len(payload) > 1 and payload[1] == 3:
            protocol = "TLS"
            return _tls(payload)
    except (ValueError, UnicodeError, IndexError) as exc:
        return StreamPayloadInfo(protocol, note=f"{exc}；未生成确定域名证据")
    return StreamPayloadInfo(note="载荷起点不是可识别的 HTTP/1 或 TLS ClientHello")
