"""对已保留数据包进行显示过滤，不改变抓包或保存的数据。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from PySide6.QtCore import QSortFilterProxyModel
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, _ICMPv6, _IPv6ExtHdr
from scapy.layers.l2 import ARP


PROTOCOLS = ("全部", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6")
MAX_HTTP_LINE_BYTES = 8192

# HTTP 方法是 token，目标和版本之间必须各有一个空格。响应状态行要求
# 三位状态码；reason-phrase 可以为空（但起始行仍需完整的 CRLF）。
_HTTP_REQUEST = re.compile(
    rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+ [^\x00-\x20\x7f]+ HTTP/1\.[01]"
)
_HTTP_RESPONSE = re.compile(rb"HTTP/1\.[01] [0-9]{3} [\t\x20-\x7e\x80-\xff]*")


def _outer_layers(packet):
    """返回最外层网络头和直属载荷，不遍历隧道或引用报文。"""
    network = packet
    while network is not None and not isinstance(network, (IP, IPv6, ARP)):
        network = getattr(network, "payload", None)
    if network is None:
        return None, None
    if isinstance(network, ARP) or isinstance(network, IP) and network.frag:
        return network, None
    transport = getattr(network, "payload", None)
    if isinstance(network, IPv6):
        while isinstance(transport, _IPv6ExtHdr):
            if isinstance(transport, IPv6ExtHdrFragment) and transport.offset:
                return network, None
            transport = getattr(transport, "payload", None)
    return network, transport


@dataclass(frozen=True)
class FilterSpec:
    """经过校验的过滤条件；非空条件之间为 AND。"""

    protocol: str = "全部"
    network: IPv4Network | IPv6Network | None = None
    port: int | None = None


def parse_filter(protocol="全部", address="", port="") -> FilterSpec:
    """校验界面输入并规范化协议、IP 地址和端口。

    Args:
        protocol: 协议选项，名称不区分大小写。
        address: 一个 IPv4、IPv6 地址或 CIDR 网段，空白表示不限。
        port: ASCII 十进制端口 0～65535，空白表示不限。

    Returns:
        可供代理模型使用的不可变过滤条件。

    Raises:
        ValueError: 输入非法。
    """
    if protocol is None:
        protocol = "全部"
    text = str(protocol).strip()
    names = {name.casefold(): name for name in PROTOCOLS}
    try:
        normalized_protocol = names[text.casefold()]
    except KeyError as exc:
        raise ValueError("请选择列表中的协议") from exc

    network = None
    if address is not None:
        address_text = str(address).strip()
    else:
        address_text = ""
    if address_text:
        try:
            # strict=False 同时接受主机地址和带主机位的 CIDR。
            network = ip_network(address_text, strict=False)
        except ValueError as exc:
            raise ValueError(
                "IP 格式不正确，请输入单个 IPv4/IPv6 地址或 CIDR 网段"
            ) from exc

    parsed_port = None
    if port is not None:
        port_text = str(port).strip()
    else:
        port_text = ""
    if port_text:
        # \d 会接受部分 Unicode 数字，过滤输入必须只允许 ASCII 十进制字符。
        if not re.fullmatch(r"[0-9]{1,5}", port_text):
            raise ValueError("端口必须是 0～65535 的十进制整数，留空表示不限")
        parsed_port = int(port_text, 10)
        if parsed_port > 65535:
            raise ValueError("端口必须在 0～65535 之间")
    return FilterSpec(normalized_protocol, network, parsed_port)


def _payload_bytes(transport) -> bytes:
    """读取直属传输层载荷，避免遍历隧道或 ICMP 引用的内层字段。"""
    payload = getattr(transport, "payload", None)
    if payload is None:
        return b""
    original = getattr(payload, "original", None)
    if isinstance(original, (bytes, bytearray, memoryview)) and original:
        return bytes(original)[:MAX_HTTP_LINE_BYTES]
    raw_load = getattr(payload, "load", None)
    if isinstance(raw_load, (bytes, bytearray, memoryview)):
        return bytes(raw_load)[:MAX_HTTP_LINE_BYTES]
    try:
        return bytes(payload)[:MAX_HTTP_LINE_BYTES]
    except Exception:
        return b""


def is_http_packet(packet) -> bool:
    """识别完整的明文 HTTP/1.0 或 HTTP/1.1 起始行。

    只检查最外层直属 TCP 载荷的前 8192 字节，因此不依赖端口、不解密
    TLS，也不会把跨 TCP 分段的行重新拼接起来。
    """
    try:
        network, transport = _outer_layers(packet)
        if not isinstance(network, (IP, IPv6)) or not isinstance(transport, TCP):
            return False
        data = _payload_bytes(transport)
        line_end = data.find(b"\r\n")
        if line_end < 0 or line_end >= MAX_HTTP_LINE_BYTES:
            return False
        line = data[:line_end]
        return bool(_HTTP_REQUEST.fullmatch(line) or _HTTP_RESPONSE.fullmatch(line))
    except Exception:
        return False


def is_icmpv6_packet(packet) -> bool:
    """识别最外层直属传输层的所有 ICMPv6 子类消息。"""
    try:
        network, transport = _outer_layers(packet)
        return isinstance(network, IPv6) and isinstance(transport, _ICMPv6)
    except Exception:
        return False


def _canonical_protocol(value) -> str | None:
    """返回协议的规范名称；未知值返回 ``None``。"""
    try:
        names = {name.casefold(): name for name in PROTOCOLS}
        return names.get(str(value).strip().casefold())
    except Exception:
        return None


def _matches_protocol(network, transport, protocol: str) -> bool:
    """按最外层网络头和直属传输层判断协议。"""
    if protocol == "全部":
        return True
    if protocol == "HTTP":
        if not isinstance(network, (IP, IPv6)) or not isinstance(transport, TCP):
            return False
        data = _payload_bytes(transport)
        line_end = data.find(b"\r\n")
        if line_end < 0 or line_end >= MAX_HTTP_LINE_BYTES:
            return False
        line = data[:line_end]
        return bool(_HTTP_REQUEST.fullmatch(line) or _HTTP_RESPONSE.fullmatch(line))
    if protocol == "IPv4":
        return isinstance(network, IP)
    if protocol == "IPv6":
        return isinstance(network, IPv6)
    if protocol == "TCP":
        return isinstance(transport, TCP)
    if protocol == "UDP":
        return isinstance(transport, UDP)
    if protocol == "ICMP":
        return isinstance(transport, ICMP)
    if protocol == "ICMPv6":
        return isinstance(network, IPv6) and isinstance(transport, _ICMPv6)
    return False


def matches_packet(packet, spec: FilterSpec) -> bool:
    """判断包是否同时满足协议、任一端 IP 和任一端 TCP/UDP 端口。

    任何字段缺失、异常或位于 ICMP 引用/隧道内层时均安全返回 False。
    """
    if not isinstance(spec, FilterSpec):
        return False
    protocol = _canonical_protocol(spec.protocol)
    if protocol is None:
        return False
    try:
        network, transport = _outer_layers(packet)
        if network is None:
            return False
        if not _matches_protocol(network, transport, protocol):
            return False

        if spec.network is not None:
            if not isinstance(network, (IP, IPv6)):
                return False
            # ip_network 的版本与网络头必须一致；仅使用最外层两个端点。
            if getattr(spec.network, "version", None) != (4 if isinstance(network, IP) else 6):
                return False
            endpoints = (getattr(network, "src", ""), getattr(network, "dst", ""))
            if not any(ip_address(value) in spec.network for value in endpoints):
                return False

        if spec.port is not None:
            if not isinstance(transport, (TCP, UDP)):
                return False
            if spec.port not in (int(transport.sport), int(transport.dport)):
                return False
        return True
    except (AttributeError, TypeError, ValueError, IndexError, OSError):
        return False


class PacketFilterModel(QSortFilterProxyModel):
    """保留源模型编号和索引，只控制哪些顶层行显示。"""

    def __init__(self, parent=None):
        """创建默认显示全部数据的代理模型。"""
        super().__init__(parent)
        self.spec = FilterSpec()
        self.domain_rows = None
        self.setDynamicSortFilter(True)

    @property
    def packets(self):
        """转发源模型数据，兼容窗口旧版的包集合访问方式。"""
        source = self.sourceModel()
        return getattr(source, "packets", ()) if source is not None else ()

    def append_batch(self, packets) -> None:
        """将批量数据追加到源模型，再由代理刷新显示。"""
        source = self.sourceModel()
        if source is not None:
            source.append_batch(packets)

    def clear(self) -> None:
        """清空源模型并重置代理行映射。"""
        source = self.sourceModel()
        if source is not None:
            source.clear()

    def _refresh_filter(self, spec: FilterSpec, domain_rows=None) -> None:
        """使用 Qt 新旧版本均可用的筛选变更通知。"""
        begin = getattr(self, "beginFilterChange", None)
        end = getattr(self, "endFilterChange", None)
        if not callable(begin) or not callable(end):
            self.spec = spec
            self.domain_rows = domain_rows
            self.invalidateFilter()
            return
        try:
            begin()
            self.spec = spec
            self.domain_rows = domain_rows
            try:
                end(QSortFilterProxyModel.Direction.Rows)
            except TypeError:
                end()
        except Exception:
            # 某些 PySide6 版本没有 Direction 枚举或尚未实现 begin/end。
            self.spec = spec
            self.domain_rows = domain_rows
            try:
                self.invalidateFilter()
            except Exception:
                pass

    def set_filter(self, spec: FilterSpec) -> None:
        """应用协议、IP 和端口条件；保留当前域名行集。"""
        if spec is None:
            spec = FilterSpec()
        if not isinstance(spec, FilterSpec):
            raise TypeError("spec 必须是 FilterSpec")
        self.set_filters(spec, self.domain_rows)

    def set_filters(self, spec: FilterSpec, domain_rows=None) -> None:
        """原子应用过滤条件和可选的源模型行集合。"""
        if spec is None:
            spec = FilterSpec()
        if not isinstance(spec, FilterSpec):
            raise TypeError("spec 必须是 FilterSpec")
        if spec == self.spec and domain_rows == self.domain_rows:
            return
        self._refresh_filter(spec, domain_rows)

    def filterAcceptsRow(self, source_row, source_parent) -> bool:
        """读取源行原始包，避免过滤后行号与详情错位。"""
        source = self.sourceModel()
        try:
            if source is None or (source_parent is not None and source_parent.isValid()):
                return False
            packets = getattr(source, "packets", None)
            if packets is None or not 0 <= int(source_row) < len(packets):
                return False
            if self.domain_rows is not None and source_row not in self.domain_rows:
                return False
            return matches_packet(packets[int(source_row)], self.spec)
        except Exception:
            return False
