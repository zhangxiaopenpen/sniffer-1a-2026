"""按需解析数据包基础列，并独立追加域名与 TCP 流分析列。"""

from datetime import datetime

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, _ICMPv6, _IPv6ExtHdr
from scapy.layers.l2 import ARP, Ether

try:
    from domain_models import AnalysisResult
except ImportError:  # pragma: no cover - 阶段4模块缺失时保持旧入口可导入
    AnalysisResult = object


def _outer_layers(packet):
    """返回最外层网络头和直属载荷，跳过 IPv6 扩展头。

    Args:
        packet: 待展示的 Scapy 数据包。

    Returns:
        网络层和直属载荷；非首分片或 ARP 不返回传输层。
    """
    network = packet
    while network and not isinstance(network, (IP, IPv6, ARP)):
        network = network.payload
    if not network:
        return None, None
    if isinstance(network, ARP) or isinstance(network, IP) and network.frag:
        return network, None
    transport = network.payload
    if isinstance(network, IPv6):
        while isinstance(transport, _IPv6ExtHdr):
            if isinstance(transport, IPv6ExtHdrFragment) and transport.offset:
                return network, None
            transport = transport.payload
    return network, transport


def packet_protocol(packet) -> str:
    """返回数据包的基础协议分类。

    Args:
        packet: 待展示的 Scapy 数据包。

    Returns:
        TCP、UDP、ICMP、ICMPv6、ARP、IPv4、IPv6 或 other。
    """
    network, transport = _outer_layers(packet)
    for layer, name in (
        (TCP, "TCP"), (UDP, "UDP"), (ICMP, "ICMP"), (_ICMPv6, "ICMPv6"),
    ):
        if isinstance(transport, layer):
            return name
    for layer, name in ((ARP, "ARP"), (IP, "IPv4"), (IPv6, "IPv6")):
        if isinstance(network, layer):
            return name
    return "other"


def packet_addresses(packet) -> tuple[str, str, str, str]:
    """提取地址和端口，非 IP 数据包回退到 ARP 或以太网地址。

    Args:
        packet: 待展示的 Scapy 数据包。

    Returns:
        源地址、目的地址、源端口和目的端口；缺失值为空字符串。
    """
    source = destination = source_port = destination_port = ""
    network, transport = _outer_layers(packet)
    source_field, destination_field = "src", "dst"
    if isinstance(network, ARP):
        source_field, destination_field = "psrc", "pdst"
    elif network is None:
        network = packet.getlayer(Ether)
    if network is not None:
        source = str(getattr(network, source_field, "") or "")
        destination = str(getattr(network, destination_field, "") or "")
    if isinstance(transport, (TCP, UDP)):
        source_port, destination_port = str(transport.sport), str(transport.dport)
    return source, destination, source_port, destination_port


def packet_time(packet) -> str:
    """把抓包时间转换为本地时间，非法或缺失时间返回短横线。

    Args:
        packet: 含 time 属性的 Scapy 数据包。

    Returns:
        精确到毫秒的本地时间文本，格式为 HH:MM:SS.mmm。
    """
    try:
        return datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
    except (AttributeError, TypeError, ValueError, OSError, OverflowError):
        return "-"


class PacketTableModel(QAbstractTableModel):
    """保存原始数据包顺序，批量插入并懒加载行显示文本。"""

    BASE_HEADERS = ["编号", "时间", "源地址", "目的地址", "协议", "源端口", "目的端口", "长度"]
    ANALYSIS_HEADERS = ["域名", "依据"]
    STREAM_HEADERS = ["TCP流", "流方向", "流状态"]

    def __init__(self, parent=None):
        """创建空模型及按行号索引的显示缓存。"""
        super().__init__(parent)
        self.packets = []
        self._rows = {}
        self.analysis_result = None
        self.stream_result = None

    @property
    def HEADERS(self):
        """返回八个基础列及当前有效的域名、TCP 流结果列。"""
        return (
            self.BASE_HEADERS
            + (self.ANALYSIS_HEADERS if self.analysis_result is not None else [])
            + (self.STREAM_HEADERS if self.stream_result is not None else [])
        )

    def rowCount(self, parent=QModelIndex()) -> int:
        """返回顶层行数；表格不提供子节点。"""
        return 0 if parent.isValid() else len(self.packets)

    def columnCount(self, parent=QModelIndex()) -> int:
        """返回当前动态列数；子节点列数为零。"""
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        """返回有效范围内的列标题或行号。"""
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal and 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        if orientation == Qt.Orientation.Vertical and 0 <= section < len(self.packets):
            return str(section + 1)
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        """缓存八个基础显示值，再按源行号读取独立分析结果。"""
        if (
            not index.isValid()
            or index.model() is not self
            or not 0 <= index.row() < len(self.packets)
            or not 0 <= index.column() < len(self.HEADERS)
        ):
            return None
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        row = index.row()
        if row not in self._rows:
            packet = self.packets[row]
            try:
                src, dst, sport, dport = packet_addresses(packet)
                original = getattr(packet, "original", None)
                size = len(original) if isinstance(original, (bytes, bytearray, memoryview)) and original else len(packet)
                self._rows[row] = (
                    str(row + 1), packet_time(packet), src or "-", dst or "-",
                    packet_protocol(packet), sport or "-", dport or "-", str(size),
                )
            except Exception:
                self._rows[row] = (str(row + 1), "-", "-", "-", "other", "-", "-", "-")
        values = self._rows[row]
        if self.analysis_result is not None:
            domain, source = self.analysis_result.row_text(row)
            values = values + (domain or "-", source or "-")
        if self.stream_result is not None:
            values = values + tuple(self.stream_result.row_text(row))
        return values[index.column()]

    def set_analysis(self, result: AnalysisResult | None) -> None:
        """原子替换分析结果并更新表头和所有可见行。"""
        if result is self.analysis_result:
            return
        self.beginResetModel()
        self.analysis_result = result
        self.endResetModel()

    def set_stream_analysis(self, result) -> None:
        """原子替换 TCP 流结果，保留域名分析和基础行缓存。

        Args:
            result: 提供 ``row_text(source_row)`` 三字符串接口的结果，
                或用于移除 TCP 流列的 ``None``。
        """
        if result is self.stream_result:
            return
        self.beginResetModel()
        self.stream_result = result
        self.endResetModel()

    def append_batch(self, packets) -> None:
        """一次追加一批原始包，不在插入期间解析数据包。

        Args:
            packets: 待追加的数据包可迭代对象，空批次不发送插入通知。
        """
        batch = list(packets)
        if not batch:
            return
        # 新数据使流快照失效；列重置必须先于行插入，避免嵌套模型通知。
        self.set_stream_analysis(None)
        start = len(self.packets)
        self.beginInsertRows(QModelIndex(), start, start + len(batch) - 1)
        self.packets.extend(batch)
        self.endInsertRows()

    def clear(self) -> None:
        """重置数据包列表和全部显示缓存。"""
        self.beginResetModel()
        self.packets.clear()
        self._rows.clear()
        self.analysis_result = None
        self.stream_result = None
        self.endResetModel()
