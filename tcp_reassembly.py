"""按捕获与序号顺序重组单方向的 TCP 载荷。"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from itertools import islice
from types import MappingProxyType

from tcp_models import (
    TCP_PROTOCOL,
    UINT32_HALF,
    UINT32_MODULUS,
    Direction,
    Endpoint,
    Flow,
    FlowKey,
    FlowState,
    Segment,
    TcpDirection,
    TcpEndpoint,
    TcpFlow,
    TcpFlowKey,
    TcpSegment,
    TcpSessionBoundary,
    TcpSessionState,
    make_segment,
    sequence_after,
    sequence_before,
    sequence_distance,
    unwrap_sequence,
)

DEFAULT_MAX_SEGMENTS = 4096
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
_CHECK_INTERVAL = 4096


@dataclass(frozen=True)
class TcpReassemblyResult:
    """单方向 TCP 重组的连续载荷、证据来源、缺口和冲突。

    序号采用展开后的半开区间。重传计数统计重叠位置上内容相同的字节，
    重叠计数还包括内容冲突的字节。源包索引仅包含实际贡献连续载荷的包。
    """

    direction: TcpDirection
    payload: bytes
    source_packet_indices: tuple[int, ...]
    start_sequence: int | None
    end_sequence: int | None
    gap_ranges: tuple[tuple[int, int], ...] = ()
    conflict: bool = False
    retransmissions: int = 0
    overlaps: int = 0
    truncated: bool = False
    has_syn: bool = False
    has_fin: bool = False
    has_rst: bool = False
    note: str = ""

    @property
    def source_rows(self) -> tuple[int, ...]:
        """返回原始包索引。"""
        return self.source_packet_indices

    @property
    def has_gap(self) -> bool:
        """是否存在未覆盖的序号区间。"""
        return bool(self.gap_ranges)

    @property
    def complete(self) -> bool:
        """已捕获的方向范围是否始于 SYN、连续且无冲突。"""
        return self.has_syn and not (
            self.has_gap or self.conflict or self.truncated
        )

    @property
    def reliable(self) -> bool:
        """是否有完整连续的载荷可供应用层解析。"""
        return bool(self.payload) and self.complete

    @property
    def status(self) -> str:
        """返回优先展示完整性问题的中文状态。"""
        if self.conflict:
            return "重叠或序号冲突"
        if self.truncated:
            return "达到限额"
        if self.has_gap:
            return "存在缺口"
        if self.has_rst:
            return "RST 关闭"
        if self.has_fin:
            return "FIN 结束"
        if self.has_syn:
            return "已重组" if self.payload else "仅控制报文"
        return "起点未知"


ReassemblyResult = TcpReassemblyResult


@dataclass(frozen=True)
class FlowReassembly:
    """一条会话的双向重组结果与连接状态。"""

    flow_key: TcpFlowKey
    directions: Mapping[TcpDirection, TcpReassemblyResult]
    state: TcpSessionState


def _gaps(
    ranges: list[tuple[int, TcpSegment]], origin: int, fin_end: int | None,
) -> tuple[tuple[int, int], ...]:
    """返回直到最后观测载荷或 FIN 之前所有未覆盖的区间。"""
    cursor = origin
    gaps: list[tuple[int, int]] = []
    for start, item in sorted(ranges, key=lambda pair: pair[0]):
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, start + len(item.payload))
    if fin_end is not None and fin_end > cursor:
        gaps.append((cursor, fin_end))
    return tuple(gaps)


def reassemble_direction(
    direction: TcpDirection,
    segments: Iterable[TcpSegment],
    *,
    max_segments: int = DEFAULT_MAX_SEGMENTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    cancel_check: Callable[[], None] | None = None,
) -> TcpReassemblyResult:
    """按 TCP 序号还原一个方向的连续载荷。

    Args:
        direction: 片段在流中的方向。
        segments: 以捕获顺序提供的同方向片段。
        max_segments: 最多分析的片段数。
        max_bytes: 从载荷起点算起的最大序号跨度。
        cancel_check: 可选回调。调用者可通过抛出异常取消重组。

    Returns:
        连续载荷和按原始包索引记录的重组结果。重叠时保留最早捕获的字节。

    Raises:
        ValueError: 预算非正，或片段方向与参数不一致。
    """
    if max_segments <= 0 or max_bytes <= 0:
        raise ValueError("TCP 重组预算必须为正数")
    items: list[TcpSegment] = []
    truncated = False
    for index, item in enumerate(islice(segments, max_segments + 1)):
        if cancel_check is not None:
            cancel_check()
        if index == max_segments:
            truncated = True
            break
        if item.direction != direction:
            raise ValueError("片段方向与重组方向不一致")
        items.append(item)

    syn = next((item for item in items if item.has_syn), None)
    syn_conflict = syn is not None and any(
        item.has_syn and item.sequence != syn.sequence for item in items
    )
    fins = [item for item in items if item.has_fin]
    has_rst = any(item.has_rst for item in items)
    payloads = [item for item in items if item.has_payload]
    if not payloads and not fins:
        return TcpReassemblyResult(direction, b"", (), None, None,
                                   truncated=truncated, has_syn=syn is not None,
                                   has_rst=has_rst, conflict=syn_conflict,
                                   note="同一方向出现不同初始序号" if syn_conflict else "")

    sequence_anchor = syn or (payloads[0] if payloads else fins[0])
    checkpoint = sequence_anchor.payload_start
    conflict = syn_conflict

    def expand_start(item: TcpSegment) -> int:
        """展开序号，并记录恰好相差半个序号空间的不确定位置。"""
        nonlocal conflict
        sequence = unwrap_sequence(item.sequence, checkpoint)
        if abs(sequence - checkpoint) == UINT32_HALF:
            conflict = True
        return sequence + int(item.has_syn)

    ranges = [(expand_start(item), item) for item in payloads]
    fin_positions = {expand_start(item) + len(item.payload) for item in fins}
    fin_end = max(fin_positions) if fin_positions else None
    origin = checkpoint if syn is not None or not ranges else min(start for start, _ in ranges)
    data_end = max((start + len(item.payload) for start, item in ranges), default=origin)
    window_end = min(data_end, origin + max_bytes)
    window_size = max(0, window_end - origin)
    truncated |= data_end > window_end or (fin_end is not None and fin_end > origin + max_bytes)
    data = bytearray(window_size)
    covered = bytearray(window_size)
    first_contribution: dict[int, int] = {}
    conflict |= any(start < origin for start, _ in ranges)
    if fin_end is not None:
        conflict |= len(fin_positions) > 1 or fin_end < max(origin, data_end)
    retransmissions = 0
    overlaps = 0

    for start, segment in ranges:
        if cancel_check is not None:
            cancel_check()
        clip_start = max(start, origin)
        clip_end = min(start + len(segment.payload), window_end)
        for chunk_start in range(clip_start, clip_end, _CHECK_INTERVAL):
            if cancel_check is not None:
                cancel_check()
            length = min(_CHECK_INTERVAL, clip_end - chunk_start)
            offset = chunk_start - origin
            end = offset + length
            chunk = segment.payload[chunk_start - start:chunk_start - start + length]
            row = segment.source_packet_index
            occupied = covered.count(1, offset, end)
            if occupied == 0:
                covered[offset:end] = b"\x01" * length
                data[offset:end] = chunk
                if row is not None:
                    first_contribution[row] = min(offset, first_contribution.get(row, offset))
            elif occupied == length and data[offset:end] == chunk:
                overlaps += length
                retransmissions += length
            else:
                for position, value in enumerate(chunk, offset):
                    if covered[position]:
                        overlaps += 1
                        if data[position] == value:
                            retransmissions += 1
                        else:
                            conflict = True
                    else:
                        covered[position] = 1
                        data[position] = value
                        if row is not None:
                            first_contribution[row] = min(
                                position, first_contribution.get(row, position)
                            )

    gaps = _gaps(ranges, origin, fin_end)
    prefix_length = min(window_size, gaps[0][0] - origin) if gaps else window_size
    source_indices = tuple(sorted(row for row, offset in first_contribution.items()
                                  if offset < prefix_length))
    notes = []
    if gaps:
        notes.append("存在序号缺口")
    if syn_conflict:
        notes.append("同一方向出现不同初始序号")
    elif conflict:
        notes.append("序号或重叠字节冲突")
    if truncated:
        notes.append("达到重组限额")
    if syn is None:
        notes.append("未观察到 SYN，流起点未知")
    return TcpReassemblyResult(
        direction=direction,
        payload=bytes(data[:prefix_length]),
        source_packet_indices=source_indices,
        start_sequence=origin,
        end_sequence=origin + prefix_length,
        gap_ranges=gaps,
        conflict=conflict,
        retransmissions=retransmissions,
        overlaps=overlaps,
        truncated=truncated,
        has_syn=syn is not None,
        has_fin=bool(fins),
        has_rst=has_rst,
        note="；".join(notes),
    )


def assemble_flow(
    flow: TcpFlow,
    *,
    max_segments: int = DEFAULT_MAX_SEGMENTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    cancel_check: Callable[[], None] | None = None,
) -> FlowReassembly:
    """重组一条会话的两个方向并返回其边界状态。

    Args:
        flow: 单条 TCP 会话及其捕获片段。
        max_segments: 两个方向合计最多分析的片段数。
        max_bytes: 每个方向最多分析的序号跨度。
        cancel_check: 可选取消回调。

    Returns:
        包含按方向索引的只读结果的会话摘要。
    """
    if max_segments <= 0 or max_bytes <= 0:
        raise ValueError("TCP 重组预算必须为正数")
    segments = tuple(islice(flow.iter_segments(), max_segments))
    truncated = len(flow.segments) > max_segments
    directions = {}
    for direction in TcpDirection:
        if cancel_check is not None:
            cancel_check()
        result = reassemble_direction(
            direction, (item for item in segments if item.direction == direction),
            max_segments=max_segments, max_bytes=max_bytes, cancel_check=cancel_check,
        )
        if truncated and not result.truncated:
            note = "；".join(filter(None, (result.note, "达到会话片段数限额")))
            result = replace(result, truncated=True, note=note)
        directions[direction] = result
    return FlowReassembly(flow.key, MappingProxyType(directions), flow.state)
