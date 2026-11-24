"""TCP 流分析的资源预算和只读结果快照。"""

from __future__ import annotations

from dataclasses import dataclass, field

from tcp_models import TcpEndpoint, TcpFlowKey


@dataclass(frozen=True)
class StreamBudget:
    """限制输入、会话和缓存载荷；载荷预算保守地包含重传字节。"""

    max_packets: int = 10_000
    max_flows: int = 1024
    max_segments_per_flow: int = 4096
    max_direction_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024

    def __post_init__(self) -> None:
        """拒绝非正或非整数预算，避免无界分析。"""
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} 必须是正整数")


@dataclass(frozen=True)
class StreamEvidence:
    """重组载荷中的直接字段及贡献字节的零基源包索引。"""

    domain: str
    source: str
    detail: str
    packet_indices: tuple[int, ...] = ()


def _endpoint_text(endpoint: TcpEndpoint) -> str:
    """为 IPv6 地址添加方括号，避免地址与端口混淆。"""
    address = f"[{endpoint.address}]" if endpoint.ip_version == 6 else endpoint.address
    return f"{address}:{endpoint.port}"


def _packet_text(indices: tuple[int, ...], maximum: int = 100) -> str:
    """限制详情中展示的包号数量，同时保留实际总数。"""
    text = "、".join(f"#{index + 1}" for index in indices[:maximum]) or "无"
    if len(indices) > maximum:
        text += f"……（共 {len(indices)} 包）"
    return text


@dataclass(frozen=True)
class FlowRecord:
    """一条双向 TCP 会话的摘要；不复制原始包或重组载荷。"""

    flow_id: int
    key: TcpFlowKey
    packet_rows: tuple[int, ...]
    domains: tuple[str, ...]
    status: str
    evidence: tuple[StreamEvidence, ...] = ()
    bytes_by_direction: tuple[int, int] = (0, 0)
    notes: tuple[str, ...] = ()
    session_id: int = 0
    statuses: tuple[str, str] = ("", "")
    retransmitted_bytes: int = 0
    overlapping_bytes: int = 0

    @property
    def endpoint_text(self) -> str:
        """返回规范化 A/B 端点，A 不表示客户端。"""
        return f"A {_endpoint_text(self.key.endpoint_a)} ↔ B {_endpoint_text(self.key.endpoint_b)}"


@dataclass(frozen=True)
class StreamAnalysisResult:
    """按稳定源行索引保存流分析，独立于 DNS 分析结果。"""

    generation: int = 0
    dataset_id: str = ""
    packet_identity: tuple[int, ...] = ()
    rows: dict[int, tuple[StreamEvidence, ...]] = field(default_factory=dict)
    row_streams: dict[int, tuple[int, str, str]] = field(default_factory=dict)
    flows: tuple[FlowRecord, ...] = ()
    warning: str = ""
    notes: tuple[str, ...] = ()

    def row_text(self, row: int) -> tuple[str, str, str]:
        """返回动态表格的流编号、方向、状态；非 TCP 行为空。"""
        item = self.row_streams.get(row)
        return (str(item[0]), item[1], item[2]) if item is not None else ("", "", "")

    def detail_text(self, row: int) -> str:
        """返回流摘要和有界证据包列表，所有包号均为原始编号。"""
        item = self.row_streams.get(row)
        lines = ["TCP 流追踪（A/B 为规范化端点，不表示客户端/服务端）"]
        if item is None:
            lines.append("该包未进入可分析的 TCP 会话。")
            if 0 <= row < len(self.notes) and self.notes[row]:
                lines.append(self.notes[row])
        else:
            flow_id, direction, status = item
            # 编号从 1 连续分配，避免每次选包遍历全部流。
            flow = self.flows[flow_id - 1]
            lines.extend((
                f"流 #{flow_id}：{flow.endpoint_text}",
                f"会话代次：{flow.session_id}；状态：{flow.status}",
                f"本包方向：{direction}；本方向状态：{status}",
                f"包数：{len(flow.packet_rows)}；连续载荷 A→B / B→A："
                f"{flow.bytes_by_direction[0]} / {flow.bytes_by_direction[1]} 字节",
                f"重复字节：{flow.retransmitted_bytes}；重叠字节：{flow.overlapping_bytes}",
                "流内原始包：" + _packet_text(flow.packet_rows),
            ))
            if flow.domains:
                lines.append("跨段域名：" + "、".join(flow.domains))
            else:
                lines.append("未获得可确认的跨段域名证据。")
            for evidence in flow.evidence:
                lines.append(f"{evidence.domain} | {evidence.source}\n"
                             f"  {evidence.detail}\n"
                             f"  连续载荷贡献包：{_packet_text(evidence.packet_indices)}")
            lines.extend("说明：" + note for note in flow.notes)
        if self.warning:
            lines.append("限额提示：" + self.warning)
        lines.append("范围：只分析已捕获的 TCP 数据；不解密 HTTPS，不识别 QUIC/HTTP3，不联网查询域名。")
        return "\n".join(lines)

    def flow_text(self) -> tuple[str, ...]:
        """返回供日志或界面使用的简短流摘要。"""
        return tuple(f"流 #{flow.flow_id} | {flow.endpoint_text} | {flow.status} | "
                     f"包 {len(flow.packet_rows)} | 域名 {','.join(flow.domains) or '无'}"
                     for flow in self.flows)
