"""对稳定包快照执行有界 TCP 流重组和可取消后台分析。"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from itertools import islice
from struct import error as StructError
from threading import Event

from PySide6.QtCore import QThread

from domain_models import AnalysisSnapshot
from stream_models import FlowRecord, StreamAnalysisResult, StreamBudget, StreamEvidence
from tcp_application import parse_stream_payload
from tcp_models import TcpDirection, TcpFlow, TcpFlowKey, TcpSessionState
from tcp_reassembly import assemble_flow
from tcp_transport import extract_tcp_segment


class StreamAnalysisCancelled(Exception):
    """用户取消分析；不发布部分结果。"""


def _check_cancel(event: Event | None) -> None:
    """在有界工作单元之间响应协作取消。"""
    if event is not None and event.is_set():
        raise StreamAnalysisCancelled()


@dataclass
class _FlowWork:
    """仅在分析线程使用的会话缓存和逐行方向映射。"""

    flow: TcpFlow
    flow_id: int
    rows: dict[int, TcpDirection] = field(default_factory=dict)
    bytes_by_direction: dict[TcpDirection, int] = field(default_factory=dict)
    limits: set[str] = field(default_factory=set)


def _snapshot(value, budget: StreamBudget) -> AnalysisSnapshot:
    """限制可迭代输入长度，再构造包对象身份稳定的快照。"""
    if isinstance(value, AnalysisSnapshot):
        snapshot = value
    else:
        snapshot = AnalysisSnapshot(0, tuple(islice(iter(value), budget.max_packets + 1)))
    if len(snapshot.packets) > budget.max_packets:
        raise ValueError(f"TCP 流分析最多支持 {budget.max_packets} 个数据包")
    return snapshot


def _collect(snapshot, budget, cancel_event, progress_callback):
    """按源行聚合会话，先检查预算再把载荷放入长期缓存。"""
    active: dict[TcpFlowKey, _FlowWork] = {}
    flows: list[_FlowWork] = []
    notes = [""] * len(snapshot.packets)
    warnings: set[str] = set()
    stored_bytes = 0
    for row, packet in enumerate(snapshot.packets):
        _check_cancel(cancel_event)
        if progress_callback and row % 32 == 0:
            progress_callback(int(40 * row / max(1, len(snapshot.packets))))
        try:
            segment = extract_tcp_segment(packet, row)
        except (ValueError, TypeError, AttributeError, IndexError, OverflowError, StructError) as exc:
            notes[row] = f"TCP 片段未纳入分析：{exc}"
            continue
        if segment is None:
            continue
        key = segment.flow_key
        current = active.get(key)
        if current is None or current.flow.needs_new_session(segment):
            session_id = current.flow.session_id + 1 if current else 0
            if len(flows) >= budget.max_flows:
                # 不把超限的新 SYN 后续数据归入同端点的旧会话。
                active.pop(key, None)
                warnings.add(f"TCP 会话数量达到 {budget.max_flows} 上限，后续新会话未分析")
                notes[row] = "TCP 会话数量达到上限，该包未分析"
                continue
            current = _FlowWork(TcpFlow(key, session_id=session_id), len(flows) + 1)
            active[key] = current
            flows.append(current)
        current.rows[row] = segment.direction
        if len(current.flow.segments) >= budget.max_segments_per_flow:
            current.limits.add(f"单会话片段数超过 {budget.max_segments_per_flow}")
            current.flow.boundary.observe(segment)
            continue
        direction_bytes = current.bytes_by_direction.get(segment.direction, 0)
        length = len(segment.payload)
        if direction_bytes + length > budget.max_direction_bytes:
            current.limits.add(f"单方向缓存载荷超过 {budget.max_direction_bytes} 字节")
        if stored_bytes + length > budget.max_total_bytes:
            current.limits.add(f"全局缓存载荷超过 {budget.max_total_bytes} 字节")
            warnings.add(f"全局 TCP 缓存载荷达到 {budget.max_total_bytes} 字节上限")
        if (direction_bytes + length > budget.max_direction_bytes
                or stored_bytes + length > budget.max_total_bytes):
            # 保留控制字段和源行，不让省略的数据产生可信证据。
            segment = replace(segment, payload=b"")
            length = 0
        current.flow.add_segment(segment)
        stored_bytes += length
        current.bytes_by_direction[segment.direction] = direction_bytes + length
    if progress_callback:
        progress_callback(40)
    return flows, notes, warnings


def _status(flow: TcpFlow, directions, limits) -> str:
    """把观测到的会话边界和数据完整性转成用户可读状态。"""
    problems = []
    if limits or any(item.truncated for item in directions):
        problems.append("达到限额")
    if any(item.conflict for item in directions):
        problems.append("重叠或序号冲突")
    if any(item.has_gap for item in directions):
        problems.append("存在缺口")
    if problems:
        return "、".join(problems)
    labels = {
        TcpSessionState.RESET: "RST 关闭",
        TcpSessionState.CLOSED: "双方 FIN 结束",
        TcpSessionState.HALF_CLOSED: "单向 FIN 结束",
        TcpSessionState.ESTABLISHED: "已观察到握手",
        TcpSessionState.OPENING: "已观察到 SYN",
        TcpSessionState.MIDSTREAM: "起点未知",
        TcpSessionState.NEW: "起点未知",
    }
    return labels[flow.state]


def _analyze_flow(work, budget, cancel_event):
    """只对整流没有缺口、冲突或截断的可靠方向解析首条消息。"""
    assembled = assemble_flow(
        work.flow,
        max_segments=budget.max_segments_per_flow,
        max_bytes=budget.max_direction_bytes,
        cancel_check=lambda: _check_cancel(cancel_event),
    )
    directions = tuple(assembled.directions[direction] for direction in TcpDirection)
    bad_stream = bool(work.limits) or any(
        item.has_gap or item.conflict or item.truncated for item in directions
    )
    evidence = []
    notes = list(sorted(work.limits))
    statuses = []
    client_directions = {segment.direction for segment in work.flow.segments
                         if segment.is_initial_syn}
    for direction, item in zip(TcpDirection, directions):
        _check_cancel(cancel_event)
        direction_text = "A→B" if direction == TcpDirection.A_TO_B else "B→A"
        statuses.append("达到限额" if work.limits else item.status)
        if item.note:
            notes.append(f"{direction_text}：{item.note}")
        if bad_stream or not item.reliable or direction not in client_directions:
            if item.payload and direction not in client_directions:
                notes.append(f"{direction_text}：未观察到该方向的初始 SYN，不生成请求域名证据")
            continue
        info = parse_stream_payload(item.payload)
        if info.note:
            notes.append(f"{direction_text}：{info.note}")
        for found in info.evidence:
            evidence.append(StreamEvidence(
                found.domain, found.source,
                f"{found.detail}；方向 {direction_text}；来源包覆盖连续载荷。",
                item.source_packet_indices,
            ))
    if bad_stream:
        notes.append("本流存在缺口、冲突或限额截断，两个方向均未生成确定域名证据")
    record = FlowRecord(
        flow_id=work.flow_id,
        key=work.flow.key,
        packet_rows=tuple(work.rows),
        domains=tuple(sorted({item.domain for item in evidence})),
        status=_status(work.flow, directions, work.limits),
        evidence=tuple(evidence),
        bytes_by_direction=tuple(len(item.payload) for item in directions),
        notes=tuple(dict.fromkeys(notes)),
        session_id=work.flow.session_id,
        statuses=tuple(statuses),
        retransmitted_bytes=sum(item.retransmissions for item in directions),
        overlapping_bytes=sum(item.overlaps for item in directions),
    )
    return record


def analyze_streams(
    snapshot_or_packets,
    cancel_event: Event | None = None,
    progress_callback=None,
    budget: StreamBudget | None = None,
) -> StreamAnalysisResult:
    """重组稳定快照中的 TCP 会话，不修改 Packet，也不发网络请求。

    Args:
        snapshot_or_packets: AnalysisSnapshot 或按源行顺序提供的包序列。
        cancel_event: 可选取消事件，取消时抛 StreamAnalysisCancelled。
        progress_callback: 接收 0 到 100 整数的后台进度回调。
        budget: 正整数资源限额；缓存字节保守地包含重复/重传载荷。

    Returns:
        完整结果及源行映射，不携带原包或额外的重组载荷副本。
    """
    budget = budget or StreamBudget()
    _check_cancel(cancel_event)
    snapshot = _snapshot(snapshot_or_packets, budget)
    flows, notes, warnings = _collect(snapshot, budget, cancel_event, progress_callback)
    records, row_streams, rows = [], {}, {}
    for position, work in enumerate(flows):
        _check_cancel(cancel_event)
        record = _analyze_flow(work, budget, cancel_event)
        records.append(record)
        for row, direction in work.rows.items():
            index = 0 if direction == TcpDirection.A_TO_B else 1
            row_streams[row] = (record.flow_id, ("A→B", "B→A")[index], record.statuses[index])
        for evidence in record.evidence:
            for row in evidence.packet_indices:
                rows.setdefault(row, []).append(evidence)
        if work.limits:
            warnings.add("部分 TCP 会话达到预算上限，详见流详情；受影响会话不生成确定域名")
        elif any(status == "达到限额" for status in record.statuses):
            warnings.add("部分 TCP 会话的序号跨度达到重组上限，未生成确定域名")
        # 释放已处理会话的副本载荷；结果只保留摘要和证据。
        work.flow.segments.clear()
        if progress_callback:
            progress_callback(40 + int(60 * (position + 1) / max(1, len(flows))))
    _check_cancel(cancel_event)
    if progress_callback:
        progress_callback(100)
    _check_cancel(cancel_event)
    return StreamAnalysisResult(
        generation=snapshot.generation,
        dataset_id=snapshot.dataset_id,
        packet_identity=snapshot.packet_identity,
        rows={row: tuple(items) for row, items in rows.items()},
        row_streams=row_streams,
        flows=tuple(records),
        warning="；".join(sorted(warnings)),
        notes=tuple(notes),
    )


class StreamAnalysisWorker(QThread):
    """后台执行流分析，只在完整成功且未取消后发布结果。"""

    def __init__(self, snapshot: AnalysisSnapshot, parent=None, budget=None):
        """保存稳定快照、预算和可供 GUI 观察的结束状态。"""
        super().__init__(parent)
        self.snapshot = snapshot
        self.budget = budget or StreamBudget()
        self.cancel_event = Event()
        self.result: StreamAnalysisResult | None = None
        self.error = ""
        self.cancelled = False
        self.progress = 0

    def request_cancel(self) -> None:
        """请求协作退出，不阻塞 GUI 或强制结束线程。"""
        self.cancel_event.set()

    def _progress(self, value: int) -> None:
        """更新供 GUI 轮询的整数进度。"""
        self.progress = value

    def run(self) -> None:
        """完成所有解析后原子发布结果，失败和取消均不发布部分结果。"""
        try:
            result = analyze_streams(self.snapshot, self.cancel_event, self._progress, self.budget)
            _check_cancel(self.cancel_event)
            self.result = result
        except StreamAnalysisCancelled:
            self.cancelled = True
        except Exception as exc:
            self.error = f"TCP 流分析失败：{exc}"
