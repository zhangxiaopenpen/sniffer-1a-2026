"""域名分析与 Qt 界面之间的生命周期辅助类。

该模块不直接操作控件，负责生成稳定快照和校验后台结果是否仍属于当前
数据集。主窗口可以将其用于实时抓包、经典 PCAP 导入和清空时的统一失效。
"""

from __future__ import annotations

from domain_models import AnalysisResult, AnalysisSnapshot


class DomainController:
    """以 generation 和包对象身份保护域名分析结果。"""

    def __init__(self) -> None:
        self.generation = 0
        self.dataset_id = ""
        self.result: AnalysisResult | None = None

    def invalidate(self) -> int:
        """使当前结果失效并返回新的数据集代次。"""
        self.generation += 1
        self.result = None
        return self.generation

    def snapshot(self, packets, dataset_id: str = "") -> AnalysisSnapshot:
        """固定当前包对象序列，供后台线程只读分析。"""
        self.dataset_id = str(dataset_id or "")
        return AnalysisSnapshot(self.generation, tuple(packets), self.dataset_id)

    def accepts(self, snapshot: AnalysisSnapshot, result: AnalysisResult, packets) -> bool:
        """判断结果是否仍对应当前代次和相同的包对象序列。"""
        return (
            snapshot.generation == self.generation
            and result.generation == self.generation
            and snapshot.dataset_id == self.dataset_id
            and snapshot.packet_identity == tuple(id(packet) for packet in packets)
        )

    def commit(self, snapshot: AnalysisSnapshot, result: AnalysisResult, packets) -> bool:
        """通过校验后提交完整结果，失败时不修改旧结果。"""
        if not self.accepts(snapshot, result, packets):
            return False
        self.result = result
        return True
