"""阶段 4 域名证据分析使用的数据模型。

模型只保存包内可回溯的分析结果，不执行网络查询，也不修改原始 Scapy
数据包。所有集合均使用元组或不可变 dataclass，便于后台线程完成后一次性
提交到 GUI。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceSource(str, Enum):
    """域名证据来源及其可信语义。"""

    DNS_QUERY = "dns_query"
    DNS_RESPONSE = "dns_response"
    HTTP_HOST = "http_host"
    TLS_SNI = "tls_sni"
    DNS_CANDIDATE = "dns_candidate"


@dataclass(frozen=True)
class DomainEvidence:
    """一项可追溯到原始包的域名证据。"""

    domain: str
    source: EvidenceSource | str
    packet_index: int
    detail: str = ""
    confidence: str = "direct"
    related_packet_indices: tuple[int, ...] = ()
    transaction_id: int | None = None
    qname: str = ""
    qtype: int | None = None
    answers: tuple[str, ...] = ()
    ttl: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.domain, str) or not self.domain:
            raise ValueError("domain 必须是非空字符串")
        if self.packet_index < 0:
            raise ValueError("packet_index 必须是非负整数")
        if self.confidence not in {"direct", "candidate"}:
            raise ValueError("confidence 必须是 direct 或 candidate")
        object.__setattr__(self, "related_packet_indices", tuple(self.related_packet_indices))
        object.__setattr__(self, "answers", tuple(str(item) for item in self.answers))


@dataclass(frozen=True)
class DNSQuestion:
    """DNS 问题区中的一个问题。"""

    qname: str
    qtype: int
    qclass: int = 1


@dataclass(frozen=True)
class DNSAnswer:
    """DNS 应答区中被阶段 4 使用的 A/AAAA/CNAME 记录。"""

    name: str
    rtype: int
    value: str
    ttl: int
    section: str = "answer"


@dataclass(frozen=True)
class DNSMessage:
    """一个完整且未跨包重组的 DNS 消息元数据。"""

    transaction_id: int
    is_response: bool
    questions: tuple[DNSQuestion, ...] = ()
    answers: tuple[DNSAnswer, ...] = ()
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    transport: str = "UDP"
    truncated: bool = False
    rcode: int = 0
    packet_index: int = -1
    timestamp: float | None = None

    @property
    def qname(self) -> str:
        """返回第一个问题名，便于表格和关联键读取。"""
        return self.questions[0].qname if self.questions else ""

    @property
    def qtype(self) -> int | None:
        """返回第一个问题类型。"""
        return self.questions[0].qtype if self.questions else None


@dataclass(frozen=True)
class DNSTransaction:
    """一个已关联的 DNS 查询/应答事务。"""

    query: DNSMessage
    response: DNSMessage | None = None
    matched: bool = False

    @property
    def packet_indices(self) -> tuple[int, ...]:
        """返回查询和应答的原始包索引。"""
        values = [self.query.packet_index]
        if self.response is not None and self.response.packet_index >= 0:
            values.append(self.response.packet_index)
        return tuple(values)


@dataclass(frozen=True)
class AnalysisBudget:
    """域名分析的有界资源预算。"""

    max_packets: int = 10_000
    max_bytes: int = 32 * 1024 * 1024
    max_name_length: int = 253
    max_dns_records: int = 64
    max_evidence_per_packet: int = 16
    max_total_evidence: int = 160_000
    dns_time_window_seconds: float = 30.0
    max_ttl_seconds: int = 7 * 24 * 60 * 60


@dataclass(frozen=True)
class AnalysisSnapshot:
    """交给后台分析线程的稳定数据集快照。"""

    generation: int
    packets: tuple[Any, ...]
    dataset_id: str = ""

    @property
    def packet_identity(self) -> tuple[int, ...]:
        """返回对象身份，用于 GUI 线程提交前的陈旧结果校验。"""
        return tuple(id(packet) for packet in self.packets)


@dataclass(frozen=True)
class AnalysisStats:
    """保存一次域名分析的统计快照。

    Attributes:
        query_count: DNS 查询消息数量。
        response_count: DNS 响应消息数量。
        matched_transaction_count: 成功关联查询与响应的事务数量。
        unmatched_query_count: 未关联到响应的查询数量。
        unique_domain_count: 分析结果中的唯一域名数量。

    Raises:
        TypeError: 当统计值不是整数时。
        ValueError: 当统计值为负数时。
    """

    query_count: int = 0
    response_count: int = 0
    matched_transaction_count: int = 0
    unmatched_query_count: int = 0
    unique_domain_count: int = 0

    def __post_init__(self) -> None:
        """校验统计值均为非负整数。"""
        for name in (
            "query_count",
            "response_count",
            "matched_transaction_count",
            "unmatched_query_count",
            "unique_domain_count",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} 必须是非负整数")
            if value < 0:
                raise ValueError(f"{name} 必须是非负整数")


@dataclass(frozen=True)
class AnalysisResult:
    """按原始包索引保存的完整分析结果。"""

    generation: int
    rows: dict[int, tuple[DomainEvidence, ...]] = field(default_factory=dict)
    dns_messages: tuple[DNSMessage, ...] = ()
    transactions: tuple[DNSTransaction, ...] = ()
    notes: tuple[str, ...] = ()
    warning: str = ""
    stats: AnalysisStats = field(default_factory=AnalysisStats)

    def row_evidence(self, row: int) -> tuple[DomainEvidence, ...]:
        """返回指定源行的证据；未知行返回空元组。"""
        return self.rows.get(int(row), ())

    def row_text(self, row: int) -> tuple[str, str]:
        """返回表格需要的域名和证据来源文本。"""
        evidence = self.row_evidence(row)
        domains = "、".join(dict.fromkeys(item.domain for item in evidence))
        sources = "、".join(dict.fromkeys(_source_label(item.source) for item in evidence))
        return domains, sources

    def rows_for_domain(self, domain: str, include_candidates: bool = False) -> frozenset[int]:
        """返回匹配确定域名的源行；候选证据默认不参与筛选。"""
        query = str(domain or "").strip().lower().rstrip(".")
        if not query:
            return frozenset(self.rows)
        result = set()
        for row, evidence in self.rows.items():
            for item in evidence:
                if item.confidence == "candidate" and not include_candidates:
                    continue
                name = item.domain.lower().rstrip(".")
                if name == query or name.endswith("." + query):
                    result.add(row)
                    break
        return frozenset(result)


def _source_label(source: EvidenceSource | str) -> str:
    """将内部证据来源转换为界面中文标签。"""
    labels = {
        EvidenceSource.DNS_QUERY.value: "DNS 查询",
        EvidenceSource.DNS_RESPONSE.value: "DNS 响应",
        EvidenceSource.HTTP_HOST.value: "HTTP Host",
        EvidenceSource.TLS_SNI.value: "TLS SNI",
        EvidenceSource.DNS_CANDIDATE.value: "DNS/IP/TTL 候选",
    }
    return labels.get(getattr(source, "value", source), str(source))
