"""从最外层 IP 的声明边界提取 TCP 片段，不解析隧道或链路填充。"""

from __future__ import annotations

import math
from ipaddress import ip_address

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import (
    IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
)
from scapy.layers.l2 import (
    CookedLinux, CookedLinuxV2, Dot1AD, Dot1Q, Ether, LLC, Loopback, SNAP,
)

from tcp_models import TcpEndpoint, TcpFlowKey, TcpSegment

MAX_LINK_HEADERS = 16
MAX_EXTENSION_HEADERS = 16
MAX_PAYLOAD_BYTES = 64 * 1024
_LINK_HEADERS = (Ether, Dot1Q, Dot1AD, Loopback, CookedLinux, CookedLinuxV2, LLC, SNAP)
_EXTENSION_HEADERS = (IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt)
_FLAG_NAMES = "FSRPAUEC"


def _outer_network(packet):
    """只越过已知链路头，返回最外层 IPv4/IPv6。"""
    layer = packet
    for _ in range(MAX_LINK_HEADERS + 1):
        if isinstance(layer, (IP, IPv6)):
            return layer
        if not isinstance(layer, _LINK_HEADERS):
            return None
        layer = layer.payload
    raise ValueError("链路层封装数量超过 16 层")


def _typed_tcp(network):
    """检查直属 TCP 对象，避免把 ICMP 引用或 IP 隧道当作外层 TCP。"""
    layer = network.payload
    for _ in range(MAX_EXTENSION_HEADERS + 1):
        if isinstance(layer, TCP):
            return layer
        if isinstance(network, IPv6) and isinstance(layer, _EXTENSION_HEADERS):
            layer = layer.payload
        else:
            return None
    raise ValueError("IPv6 扩展头数量超过 16 层")


def _ipv4_bounds(raw: memoryview) -> tuple[int, int, int, str, str]:
    """校验 IPv4 长度及分片标志，返回 TCP 前的边界与端点地址。"""
    if len(raw) < 20 or raw[0] >> 4 != 4:
        raise ValueError("IPv4 头部不完整或版本错误")
    offset = (raw[0] & 15) * 4
    end = int.from_bytes(raw[2:4], "big")
    if offset < 20 or offset > len(raw) or end < offset:
        raise ValueError("IPv4 头长度或总长度不合法")
    if end > len(raw):
        raise ValueError("IPv4 报文捕获截断")
    if int.from_bytes(raw[6:8], "big") & 0x3FFF:
        raise ValueError("IPv4 分片未重组，跳过 TCP 流片段")
    return (offset, end, raw[9], str(ip_address(bytes(raw[12:16]))),
            str(ip_address(bytes(raw[16:20]))))


def _ipv6_bounds(raw: memoryview) -> tuple[int, int, int, str, str]:
    """校验普通 IPv6 扩展头，拒绝分片和声明范围外的内容。"""
    if len(raw) < 40 or raw[0] >> 4 != 6:
        raise ValueError("IPv6 头部不完整或版本错误")
    end = 40 + int.from_bytes(raw[4:6], "big")
    if end > len(raw):
        raise ValueError("IPv6 报文捕获截断")
    source = str(ip_address(bytes(raw[8:24])))
    destination = str(ip_address(bytes(raw[24:40])))
    offset, protocol = 40, raw[6]
    for count in range(MAX_EXTENSION_HEADERS + 1):
        if protocol == 44:
            raise ValueError("IPv6 分片未重组，跳过 TCP 流片段")
        if protocol not in (0, 43, 60):
            return offset, end, protocol, source, destination
        if count == MAX_EXTENSION_HEADERS:
            raise ValueError("IPv6 扩展头数量超过 16 层")
        if offset + 2 > end:
            raise ValueError("IPv6 扩展头捕获截断")
        following = raw[offset]
        size = (raw[offset + 1] + 1) * 8
        if offset + size > end:
            raise ValueError("IPv6 扩展头声明长度超出报文")
        offset, protocol = offset + size, following
    raise ValueError("IPv6 扩展头数量超限")


def _packet_time(packet) -> float | None:
    """保留有限时间戳，无效值不影响按源包顺序分析。"""
    try:
        value = float(packet.time)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    return value if math.isfinite(value) else None


def extract_tcp_segment(packet, packet_index: int) -> TcpSegment | None:
    """提取最外层 IP 中的 TCP 控制字段和真实应用字节。

    Args:
        packet: 原始 Scapy 包；仅只读访问，不修改字段或载荷。
        packet_index: 稳定快照中从零开始的原始包索引。

    Returns:
        TCP 片段；非外层 TCP 或不支持的封装返回 None。

    Raises:
        ValueError: 报头不完整、长度非法、IP 分片或封装数量超限。
    """
    network = _outer_network(packet)
    if network is None:
        return None
    original = getattr(network, "original", None)
    raw = memoryview(original if original else bytes(network))
    bounds = _ipv4_bounds(raw) if isinstance(network, IP) else _ipv6_bounds(raw)
    offset, end, protocol, source, destination = bounds
    if protocol != 6:
        if _typed_tcp(network) is not None:
            raise ValueError("TCP 层与 IP 声明的协议号不一致")
        return None
    if offset + 20 > end:
        raise ValueError("TCP 头部捕获截断或超出 IP 声明范围")
    header_length = (raw[offset + 12] >> 4) * 4
    if header_length < 20 or offset + header_length > end:
        raise ValueError("TCP dataofs 声明长度不合法")
    start = offset + header_length
    if end - start > MAX_PAYLOAD_BYTES:
        raise ValueError("TCP 应用载荷超过 64 KiB 限制")
    sport = int.from_bytes(raw[offset:offset + 2], "big")
    dport = int.from_bytes(raw[offset + 2:offset + 4], "big")
    key = TcpFlowKey.from_values(source, sport, destination, dport)
    direction = key.direction_for(TcpEndpoint(source, sport), TcpEndpoint(destination, dport))
    flags = frozenset(name for bit, name in enumerate(_FLAG_NAMES)
                      if raw[offset + 13] & (1 << bit))
    wire_length = getattr(packet, "wirelen", None)
    return TcpSegment(
        flow_key=key,
        direction=direction,
        sequence=int.from_bytes(raw[offset + 4:offset + 8], "big"),
        acknowledgement=int.from_bytes(raw[offset + 8:offset + 12], "big"),
        flags=flags,
        payload=bytes(raw[start:end]),
        timestamp=_packet_time(packet),
        source_packet_index=packet_index,
        wire_length=int(wire_length) if wire_length is not None else None,
    )
