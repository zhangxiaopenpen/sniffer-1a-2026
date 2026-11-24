"""阶段 4 域名证据分析和后台 Worker。"""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal, InvalidOperation
from threading import Event

from PySide6.QtCore import QThread

from domain_models import (
    AnalysisBudget,
    AnalysisResult,
    AnalysisStats,
    AnalysisSnapshot,
    DNSMessage,
    DNSTransaction,
    DomainEvidence,
    EvidenceSource,
)
from domain_parsers import PacketParseResult, analyze_packet


class AnalysisCancelled(Exception):
    """分析被取消，调用方不得提交不完整结果。"""


def _check_cancel(cancel_event: Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisCancelled()


def _packet_size(packet) -> int:
    original = getattr(packet, "original", None)
    if isinstance(original, (bytes, bytearray, memoryview)) and original:
        return len(original)
    try:
        return len(packet)
    except Exception:
        return 0


def _timestamp(packet) -> float | None:
    try:
        value = Decimal(str(packet.time))
        return float(value) if value.is_finite() else None
    except (AttributeError, TypeError, ValueError, InvalidOperation, OverflowError):
        return None


def _direct_evidence(result: PacketParseResult) -> tuple[DomainEvidence, ...]:
    return tuple(result.evidence)


def _build_analysis_stats(
    messages,
    transactions,
    rows,
) -> AnalysisStats:
    """Build the aggregate statistics from the final DNS and evidence data.

    ``transactions`` can contain an unmatched response represented by a
    transaction whose ``query`` is that response.  Such a transaction must
    not count as a matched query/response pair, so matched query packet
    indices are taken only from transactions with both ``matched`` and a
    response.
    """
    message_items = tuple(messages)
    transaction_items = tuple(transactions)
    query_messages = tuple(message for message in message_items if not message.is_response)
    response_messages = tuple(message for message in message_items if message.is_response)
    matched_query_indices = {
        transaction.query.packet_index
        for transaction in transaction_items
        if transaction.matched and transaction.response is not None
    }
    query_indices = {message.packet_index for message in query_messages}
    unique_domains = {
        evidence.domain.casefold().rstrip(".")
        for evidence_items in rows.values()
        for evidence in evidence_items
        if evidence.confidence == "direct"
    }
    return AnalysisStats(
        query_count=len(query_messages),
        response_count=len(response_messages),
        matched_transaction_count=sum(
            1
            for transaction in transaction_items
            if transaction.matched and transaction.response is not None
        ),
        unmatched_query_count=len(query_indices - matched_query_indices),
        unique_domain_count=len(unique_domains),
    )


def _same_dns_key(query: DNSMessage, response: DNSMessage, window: float) -> bool:
    if query.is_response or not response.is_response:
        return False
    if query.transaction_id != response.transaction_id:
        return False
    if query.transport.upper() != response.transport.upper():
        return False
    if query.source_ip != response.destination_ip or query.destination_ip != response.source_ip:
        return False
    if query.qname.casefold().rstrip(".") != response.qname.casefold().rstrip("."):
        return False
    if query.qtype != response.qtype:
        return False
    if query.timestamp is None or response.timestamp is None:
        return False
    return query.timestamp <= response.timestamp and response.timestamp - query.timestamp <= window


def _row_address(packet):
    try:
        network = packet
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP
        while network is not None and not isinstance(network, (IP, IPv6, ARP)):
            network = getattr(network, "payload", None)
        transport = getattr(network, "payload", None) if network is not None else None
        source = str(getattr(network, "src", ""))
        destination = str(getattr(network, "dst", ""))
        return source, destination, int(getattr(transport, "sport", 0)), int(getattr(transport, "dport", 0))
    except (AttributeError, TypeError, ValueError):
        return "", "", 0, 0


def analyze_packets(
    packets,
    *,
    generation: int = 0,
    cancel_event: Event | None = None,
    progress_callback=None,
    budget: AnalysisBudget | None = None,
) -> AnalysisResult:
    """分析稳定包快照并返回完整结果。"""
    budget = budget or AnalysisBudget()
    packet_tuple = tuple(packets)
    if len(packet_tuple) > budget.max_packets:
        raise ValueError(f"分析最多支持 {budget.max_packets} 个数据包")
    total_bytes = 0
    for packet in packet_tuple:
        _check_cancel(cancel_event)
        total_bytes += _packet_size(packet)
        if total_bytes > budget.max_bytes:
            raise ValueError(f"分析原始数据超过 {budget.max_bytes} 字节预算")
    rows: dict[int, list[DomainEvidence]] = {index: [] for index in range(len(packet_tuple))}
    notes = [""] * len(packet_tuple)
    parsed: list[PacketParseResult] = []
    messages: list[DNSMessage] = []
    events: list[tuple[float, int]] = []
    if progress_callback:
        progress_callback(0)
    for index, packet in enumerate(packet_tuple):
        _check_cancel(cancel_event)
        result = analyze_packet(packet, index)
        if any(len(item.domain) > budget.max_name_length for item in result.evidence):
            result = replace(result, evidence=(), note="域名长度超过当前分析预算，未提取证据")
        if result.dns_message is not None and len(result.dns_message.questions) + len(result.dns_message.answers) > budget.max_dns_records:
            result = replace(result, evidence=(), note="DNS 记录数量超过当前分析预算，未提取证据")
        parsed.append(result)
        notes[index] = result.note
        for evidence in _direct_evidence(result)[:budget.max_evidence_per_packet]:
            rows[index].append(evidence)
        if result.dns_message is not None:
            messages.append(result.dns_message)
        timestamp = _timestamp(packet)
        if timestamp is not None:
            events.append((timestamp, index))
        elif result.dns_message is not None:
            notes[index] = "; ".join(filter(None, (notes[index], "时间戳无效，未进行 DNS 事务关联")))
        if progress_callback:
            progress_callback(int(50 * (index + 1) / max(1, len(packet_tuple))))

    queries = [item for item in messages if not item.is_response]
    responses = [item for item in messages if item.is_response]
    used_queries: set[int] = set()
    transactions: list[DNSTransaction] = []
    query_index: dict[tuple, list[DNSMessage]] = {}
    for query in queries:
        query_index.setdefault((query.transport, query.transaction_id, query.qname.casefold().rstrip("."), query.qtype, query.source_ip, query.destination_ip), []).append(query)
    bindings: dict[tuple[str, str], list[tuple[str, float, float, int]]] = {}
    binding_count = 0
    for response in sorted(responses, key=lambda item: item.timestamp if item.timestamp is not None else float("inf")):
        _check_cancel(cancel_event)
        key = (response.transport, response.transaction_id, response.qname.casefold().rstrip("."), response.qtype, response.destination_ip, response.source_ip)
        candidates = [query for query in query_index.get(key, ()) if query.packet_index not in used_queries and _same_dns_key(query, response, budget.dns_time_window_seconds)]
        query = min(candidates, key=lambda item: abs((response.timestamp or 0) - (item.timestamp or 0))) if candidates else None
        matched = query is not None
        transactions.append(DNSTransaction(query or response, response, matched))
        if query is None:
            if 0 <= response.packet_index < len(notes):
                notes[response.packet_index] = "; ".join(
                    filter(None, (notes[response.packet_index], "未匹配本次抓包中的 DNS 查询"))
                )
            continue
        used_queries.add(query.packet_index)
        for answer in response.answers:
            if answer.rtype not in (1, 28):
                continue
            ttl = min(max(0, answer.ttl), budget.max_ttl_seconds)
            if ttl <= 0 or response.timestamp is None:
                continue
            if binding_count >= budget.max_total_evidence:
                continue
            bindings.setdefault((query.source_ip, answer.value), []).append((query.qname, response.timestamp, response.timestamp + ttl, response.packet_index))
            binding_count += 1
        for row in (query.packet_index, response.packet_index):
            if 0 <= row < len(rows):
                rows[row] = list(rows[row])
                for index, item in enumerate(rows[row]):
                    if item.source in (EvidenceSource.DNS_QUERY, EvidenceSource.DNS_RESPONSE):
                        rows[row][index] = DomainEvidence(
                            item.domain, item.source, item.packet_index, item.detail,
                            item.confidence,
                            tuple(sorted(set(item.related_packet_indices + tuple(i for i in (query.packet_index, response.packet_index) if i != row)))),
                            response.transaction_id, item.qname or query.qname,
                            item.qtype if item.qtype is not None else query.qtype,
                            item.answers, item.ttl,
                        )

    if bindings:
        for timestamp, row in sorted(events):
            _check_cancel(cancel_event)
            if any(item.packet_index == row for item in messages):
                continue
            source, destination, _, _ = _row_address(packet_tuple[row])
            for client, address in ((source, destination), (destination, source)):
                for domain, start, expiry, origin in bindings.get((client, address), ()):
                    if timestamp < start or timestamp > expiry:
                        continue
                    rows[row].append(DomainEvidence(
                        domain, EvidenceSource.DNS_CANDIDATE, row,
                        f"来自 DNS 响应包 #{origin + 1} 的地址/TTL 候选；共享 IP 不能确认网站归属",
                        "candidate", (origin,), ttl=max(0, int(expiry - timestamp)),
                    ))
                    break
    total_evidence = 0
    for row in rows:
        unique = []
        seen = set()
        for item in rows[row]:
            key = (item.domain, item.source, item.packet_index, item.detail)
            if key not in seen and len(unique) < budget.max_evidence_per_packet and total_evidence < budget.max_total_evidence:
                seen.add(key)
                unique.append(item)
                total_evidence += 1
        rows[row] = unique
    if progress_callback:
        progress_callback(100)
    _check_cancel(cancel_event)
    stats = _build_analysis_stats(messages, transactions, rows)
    return AnalysisResult(
        generation=generation,
        rows={row: tuple(items) for row, items in rows.items()},
        dns_messages=tuple(sorted(messages, key=lambda item: item.packet_index)),
        transactions=tuple(transactions),
        notes=tuple(notes),
        stats=stats,
    )


class DomainAnalysisWorker(QThread):
    """后台分析稳定快照，只发布完整结果。"""

    def __init__(self, snapshot: AnalysisSnapshot, budget: AnalysisBudget | None = None, parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self.budget = budget or AnalysisBudget()
        self.cancel_event = Event()
        self.result: AnalysisResult | None = None
        self.error = ""
        self.cancelled = False
        self.progress = 0

    def request_cancel(self) -> None:
        self.cancel_event.set()

    def _progress(self, value: int) -> None:
        self.progress = max(0, min(100, int(value)))

    def run(self) -> None:
        try:
            result = analyze_packets(
                self.snapshot.packets,
                generation=self.snapshot.generation,
                cancel_event=self.cancel_event,
                progress_callback=self._progress,
                budget=self.budget,
            )
            _check_cancel(self.cancel_event)
            self.result = result
        except AnalysisCancelled:
            self.cancelled = True
        except Exception as exc:
            self.error = f"域名分析失败：{exc}"
