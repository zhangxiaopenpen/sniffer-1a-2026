"""TCP 端点、捕获片段、会话边界和序号模型。"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Iterable, Iterator

UINT32_MODULUS = 1 << 32
UINT32_HALF = 1 << 31
TCP_PROTOCOL = "TCP"


class TcpDirection(str, Enum):
    """片段相对于规范化流端点的方向。"""

    A_TO_B = "a_to_b"
    B_TO_A = "b_to_a"


class TcpSessionState(str, Enum):
    """根据观测到的 TCP 边界标志推导的会话状态。"""

    NEW = "new"
    OPENING = "opening"
    ESTABLISHED = "established"
    MIDSTREAM = "midstream"
    HALF_CLOSED = "half_closed"
    CLOSED = "closed"
    RESET = "reset"


@dataclass(frozen=True, order=True)
class TcpEndpoint:
    """规范化的 IP 地址和 TCP 端口。

    Args:
        address: IPv4 或 IPv6 文本地址。初始化时会压缩 IPv6 表示。
        port: TCP 端口，范围为 0 到 65535。
    """

    address: str
    port: int

    def __post_init__(self) -> None:
        """验证并规范化地址与端口。"""
        parsed = ipaddress.ip_address(str(self.address))
        normalized_port = int(self.port)
        if not 0 <= normalized_port <= 65535:
            raise ValueError("TCP 端口必须在 0 到 65535 之间")
        object.__setattr__(self, "address", parsed.compressed)
        object.__setattr__(self, "port", normalized_port)

    @property
    def ip_version(self) -> int:
        """返回端点的 IP 版本。"""
        return ipaddress.ip_address(self.address).version

    @property
    def sort_key(self) -> tuple[int, str, int]:
        """返回用于规范化双向流键的稳定排序键。"""
        return self.ip_version, self.address, self.port


@dataclass(frozen=True)
class TcpFlowKey:
    """不区分传输方向的 TCP 双向流标识。

    ``endpoint_a`` 和 ``endpoint_b`` 按地址族、地址、端口排序。同一条连接
    由任意方向创建时都会得到相同的键，方向信息通过 :meth:`direction_for`
    和 :meth:`endpoints_for` 保留。
    """

    endpoint_a: TcpEndpoint
    endpoint_b: TcpEndpoint
    protocol: str = TCP_PROTOCOL

    def __post_init__(self) -> None:
        """验证端点版本、端点唯一性和协议。"""
        if self.endpoint_a.ip_version != self.endpoint_b.ip_version:
            raise ValueError("同一 TCP 流的两个端点必须使用相同 IP 版本")
        if self.endpoint_a == self.endpoint_b:
            raise ValueError("TCP 流的两端不能相同")
        protocol = str(self.protocol).upper()
        if protocol != TCP_PROTOCOL:
            raise ValueError("当前只支持 TCP 流")
        object.__setattr__(self, "protocol", protocol)
        first, second = sorted((self.endpoint_a, self.endpoint_b), key=lambda item: item.sort_key)
        object.__setattr__(self, "endpoint_a", first)
        object.__setattr__(self, "endpoint_b", second)

    @classmethod
    def from_endpoints(
        cls,
        source: TcpEndpoint,
        destination: TcpEndpoint,
        protocol: str = TCP_PROTOCOL,
    ) -> "TcpFlowKey":
        """从任意方向的端点创建规范化流键。"""
        return cls(source, destination, protocol)

    @classmethod
    def from_values(
        cls,
        source_address: str,
        source_port: int,
        destination_address: str,
        destination_port: int,
        protocol: str = TCP_PROTOCOL,
    ) -> "TcpFlowKey":
        """从地址和端口创建规范化流键。"""
        return cls(
            TcpEndpoint(source_address, source_port),
            TcpEndpoint(destination_address, destination_port),
            protocol,
        )

    def direction_for(self, source: TcpEndpoint, destination: TcpEndpoint) -> TcpDirection:
        """返回一条片段相对于本流的方向。"""
        if source == self.endpoint_a and destination == self.endpoint_b:
            return TcpDirection.A_TO_B
        if source == self.endpoint_b and destination == self.endpoint_a:
            return TcpDirection.B_TO_A
        raise ValueError("片段端点不属于当前 TCP 流")

    def endpoints_for(self, direction: TcpDirection) -> tuple[TcpEndpoint, TcpEndpoint]:
        """返回给定方向的源端点和目的端点。"""
        if direction == TcpDirection.A_TO_B:
            return self.endpoint_a, self.endpoint_b
        if direction == TcpDirection.B_TO_A:
            return self.endpoint_b, self.endpoint_a
        raise ValueError(f"未知 TCP 流方向: {direction!r}")


_ALLOWED_FLAGS = frozenset("SAFRPU E C".replace(" ", ""))


@dataclass(frozen=True)
class TcpSegment:
    """捕获到的一条 TCP 片段。

    ``source_packet_index`` 是稳定快照中的原始行号，用于把流结果映射回
    数据包表格。模型保存线上 32 位序号，后续重组器负责序号回绕展开。
    """

    flow_key: TcpFlowKey
    direction: TcpDirection
    sequence: int
    acknowledgement: int | None = None
    flags: FrozenSet[str] = frozenset()
    payload: bytes = b""
    timestamp: float | None = None
    source_packet_index: int | None = None
    wire_length: int | None = None

    def __post_init__(self) -> None:
        """验证序号、标志位、载荷和源数据包索引。"""
        sequence = int(self.sequence)
        if not 0 <= sequence < UINT32_MODULUS:
            raise ValueError("TCP 序号必须在 0 到 2^32-1 之间")
        object.__setattr__(self, "sequence", sequence)
        if self.acknowledgement is not None:
            acknowledgement = int(self.acknowledgement)
            if not 0 <= acknowledgement < UINT32_MODULUS:
                raise ValueError("TCP 确认号必须在 0 到 2^32-1 之间")
            object.__setattr__(self, "acknowledgement", acknowledgement)
        payload = bytes(self.payload)
        object.__setattr__(self, "payload", payload)
        normalized_flags = frozenset(str(flag).upper() for flag in self.flags)
        unknown = normalized_flags - _ALLOWED_FLAGS
        if unknown:
            raise ValueError(f"未知 TCP 标志位: {sorted(unknown)}")
        object.__setattr__(self, "flags", normalized_flags)
        if self.source_packet_index is not None and int(self.source_packet_index) < 0:
            raise ValueError("原始数据包索引不能为负数")
        if self.wire_length is not None and int(self.wire_length) < len(payload):
            raise ValueError("线路长度不能小于 TCP 载荷长度")

    @property
    def source_row(self) -> int | None:
        """返回源数据包行号的兼容别名。"""
        return self.source_packet_index

    @property
    def has_payload(self) -> bool:
        """是否携带应用层载荷。"""
        return bool(self.payload)

    @property
    def has_syn(self) -> bool:
        """是否带有 SYN 标志。"""
        return "S" in self.flags

    @property
    def is_initial_syn(self) -> bool:
        """是否为发起会话的 SYN。"""
        return self.has_syn and "A" not in self.flags

    @property
    def has_fin(self) -> bool:
        """是否带有 FIN 标志。"""
        return "F" in self.flags

    @property
    def has_rst(self) -> bool:
        """是否带有 RST 标志。"""
        return "R" in self.flags

    @property
    def payload_start(self) -> int:
        """返回应用载荷在 TCP 序号空间中的起点。"""
        return self.sequence + int(self.has_syn)

    @property
    def payload_end(self) -> int:
        """返回不考虑序号回绕的载荷末端。"""
        return self.payload_start + len(self.payload)

    @property
    def is_boundary(self) -> bool:
        """是否包含 SYN、FIN 或 RST 会话边界标志。"""
        return self.has_syn or self.has_fin or self.has_rst


@dataclass
class TcpSessionBoundary:
    """记录一个双向流的会话边界观测结果。"""

    syn_directions: set[TcpDirection] = field(default_factory=set)
    fin_directions: set[TcpDirection] = field(default_factory=set)
    rst_seen: bool = False
    payload_before_syn: bool = False

    def observe(self, segment: TcpSegment) -> None:
        """根据片段更新边界观测结果。"""
        if segment.has_syn:
            self.syn_directions.add(segment.direction)
        if segment.has_fin:
            self.fin_directions.add(segment.direction)
        if segment.has_rst:
            self.rst_seen = True
        if segment.payload and not self.syn_directions:
            self.payload_before_syn = True

    @property
    def state(self) -> TcpSessionState:
        """根据当前观测推导会话状态。"""
        if self.rst_seen:
            return TcpSessionState.RESET
        if len(self.fin_directions) >= 2:
            return TcpSessionState.CLOSED
        if self.fin_directions:
            return TcpSessionState.HALF_CLOSED
        if self.payload_before_syn and not self.syn_directions:
            return TcpSessionState.MIDSTREAM
        if len(self.syn_directions) >= 2:
            return TcpSessionState.ESTABLISHED
        if self.syn_directions:
            return TcpSessionState.OPENING
        return TcpSessionState.NEW


def unwrap_sequence(sequence: int, checkpoint: int) -> int:
    """将线上 32 位序号展开到最接近检查点的整数序号。

    Args:
        sequence: 报文中的 32 位 TCP 序号。
        checkpoint: 同一方向已知的整数序号，可跨越回绕边界。

    Returns:
        与 ``checkpoint`` 距离最短的展开序号。
    """
    sequence = int(sequence)
    if not 0 <= sequence < UINT32_MODULUS:
        raise ValueError("TCP 序号必须在 0 到 2^32-1 之间")
    checkpoint = int(checkpoint)
    candidate = (checkpoint & ~(UINT32_MODULUS - 1)) | sequence
    if candidate - checkpoint > UINT32_HALF:
        candidate -= UINT32_MODULUS
    elif checkpoint - candidate > UINT32_HALF:
        candidate += UINT32_MODULUS
    return candidate


def sequence_distance(left: int, right: int) -> int:
    """返回两个线上序号的有符号模距离。"""
    left = int(left) % UINT32_MODULUS
    right = int(right) % UINT32_MODULUS
    distance = (left - right) % UINT32_MODULUS
    return distance - UINT32_MODULUS if distance >= UINT32_HALF else distance


def sequence_before(left: int, right: int) -> bool:
    """判断线上序号 ``left`` 是否位于 ``right`` 之前。"""
    return sequence_distance(left, right) < 0


def sequence_after(left: int, right: int) -> bool:
    """判断线上序号 ``left`` 是否位于 ``right`` 之后。"""
    return sequence_distance(left, right) > 0


def make_segment(
    flow_key: TcpFlowKey,
    source: TcpEndpoint,
    destination: TcpEndpoint,
    sequence: int,
    acknowledgement: int | None = None,
    payload: bytes = b"",
    flags: Iterable[str] = (),
    timestamp: float | None = None,
    wire_length: int | None = None,
    source_packet_index: int | None = None,
    source_row: int | None = None,
) -> TcpSegment:
    """根据两个端点创建带方向的 TCP 片段。

    ``source_row`` 是旧调用方使用的参数名，与 ``source_packet_index`` 等价。
    """
    if source_packet_index is not None and source_row is not None:
        raise ValueError("source_packet_index 和 source_row 只能指定一个")
    row = source_packet_index if source_packet_index is not None else source_row
    direction = flow_key.direction_for(source, destination)
    return TcpSegment(flow_key, direction, sequence, acknowledgement,
                      frozenset(flags), payload, timestamp, row, wire_length)


@dataclass
class TcpFlow:
    """同一双向 TCP 流的捕获片段容器。

    流容器只负责保留原始片段、边界状态和会话代次。它不会排序、去重或
    合并载荷，后续重组器可通过 ``iter_segments`` 和 ``sequence_ranges``
    消费这些稳定记录。
    """

    key: TcpFlowKey
    session_id: int = 0
    segments: list[TcpSegment] = field(default_factory=list)
    boundary: TcpSessionBoundary = field(default_factory=TcpSessionBoundary)

    def needs_new_session(self, segment: TcpSegment) -> bool:
        """检查片段是否应进入独立的会话容器。"""
        if segment.flow_key != self.key:
            raise ValueError("片段不属于当前 TCP 流")
        if self.state in (TcpSessionState.CLOSED, TcpSessionState.RESET):
            return segment.is_initial_syn or segment.has_payload
        # FIN 结束本方向发送。晚捕获的数据无法确认归属，单独记录该段。
        if segment.has_payload and segment.direction in self.boundary.fin_directions:
            return True
        if not segment.is_initial_syn:
            return False
        previous_syn = next((item for item in self.iter_segments(segment.direction)
                             if item.has_syn), None)
        if previous_syn is not None:
            return previous_syn.sequence != segment.sequence
        if self.boundary.payload_before_syn or self.boundary.fin_directions:
            return True
        return any(item.is_initial_syn or item.has_payload for item in self.segments)

    def add_segment(self, segment: TcpSegment) -> None:
        """按捕获顺序追加片段。

        Raises:
            ValueError: 片段属于其他流或新的会话。
        """
        if self.needs_new_session(segment):
            raise ValueError("片段发起了新的 TCP 会话")
        self.segments.append(segment)
        self.boundary.observe(segment)

    @property
    def segments_seen(self) -> list[TcpSegment]:
        """返回片段列表的兼容名称。"""
        return self.segments

    @property
    def state(self) -> TcpSessionState:
        """返回当前会话边界状态。"""
        return self.boundary.state

    def iter_segments(self, direction: TcpDirection | None = None) -> Iterator[TcpSegment]:
        """按捕获顺序迭代全部片段或指定方向片段。"""
        return (item for item in self.segments
                if direction is None or item.direction == direction)

    def sequence_ranges(self, direction: TcpDirection) -> tuple[tuple[int, int], ...]:
        """返回指定方向的原始序号范围，不填补缺口和合并重叠。"""
        return tuple(
            (item.payload_start, item.payload_end)
            for item in self.iter_segments(direction)
            if item.has_payload or item.is_boundary
        )

    @property
    def source_packet_indices(self) -> tuple[int, ...]:
        """返回按首次捕获顺序去重后的源数据包索引。"""
        return tuple(dict.fromkeys(
            item.source_packet_index for item in self.segments
            if item.source_packet_index is not None
        ))




# 简短别名便于后续模块表达基础模型，同时保留 Tcp 前缀作为公开名称。
Direction = TcpDirection
Endpoint = TcpEndpoint
FlowKey = TcpFlowKey
Segment = TcpSegment
FlowState = TcpSessionState
Flow = TcpFlow
