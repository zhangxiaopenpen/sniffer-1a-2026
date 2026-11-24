"""TCP 流分析的快照校验与窗口操作，独立于 DNS 分析结果。"""

from __future__ import annotations

from domain_models import AnalysisSnapshot
from stream_analysis import StreamAnalysisWorker


class StreamController:
    """用数据集代次、来源标识和包对象序列校验完整结果。"""

    def __init__(self) -> None:
        """初始化独立的 TCP 流分析状态。"""
        self.generation = 0
        self.dataset_id = ""
        self.result = None

    def snapshot(self, packets, dataset_id: str = "") -> AnalysisSnapshot:
        """固定当前对象序列，供后台线程只读分析。"""
        self.dataset_id = str(dataset_id)
        return AnalysisSnapshot(self.generation, tuple(packets), self.dataset_id)

    def invalidate(self) -> int:
        """递增代次并清除旧结果，使正在执行的快照失效。"""
        self.generation += 1
        self.result = None
        return self.generation

    def accepts(self, snapshot, result, packets, dataset_id: str | None = None) -> bool:
        """确认快照、结果和当前数据集完全匹配。

        Args:
            snapshot: 启动线程时保存的快照。
            result: 已完成的流分析结果。
            packets: 当前窗口保留的原始数据包。
            dataset_id: 当前文件路径或实时数据集标识。

        Returns:
            三方元数据及包对象身份一致时返回 True。
        """
        identity = tuple(id(packet) for packet in packets)
        current_dataset = self.dataset_id if dataset_id is None else str(dataset_id)
        return (
            snapshot.generation == self.generation == result.generation
            and snapshot.dataset_id == self.dataset_id == result.dataset_id == current_dataset
            and snapshot.packet_identity == tuple(result.packet_identity) == identity
        )

    def commit(self, snapshot, result, packets, dataset_id: str | None = None) -> bool:
        """校验通过后原子替换结果；拒绝时保留旧结果。"""
        if not self.accepts(snapshot, result, packets, dataset_id):
            return False
        self.result = result
        return True


class StreamWindowMixin:
    """向主窗口提供 TCP 流分析操作，不持有第二份原始包。"""

    def start_stream_analysis(self) -> None:
        """对空闲窗口的稳定包快照启动后台流分析。"""
        if self.is_busy() or self._closing or self.buffer.snapshot().pending or not self.packets:
            return
        snapshot = self.stream_controller.snapshot(self.packets, self.source_file or "live")
        self._stream_cancel_requested = False
        worker = None
        try:
            worker = StreamAnalysisWorker(snapshot, parent=self)
            self.stream_thread = worker
            worker.start()
        except Exception as exc:
            self.stream_thread = None
            if worker is not None:
                worker.deleteLater()
            self.state = "error"
            self.notice = f"无法开始 TCP 流分析：{exc}"
            self._show_stream_summary()
        else:
            self.state = "stream_analysing"
            self.notice = "正在重组 TCP 流，完成后可选中数据包查看流详情"
            self.stream_status_label.setText("TCP流：正在分析 0%")
        self.update_controls()
        self.update_status()

    def _invalidate_stream_analysis(self) -> None:
        """使旧结果和旧快照失效；线程引用保留至其退出。"""
        if self.stream_thread is not None:
            self._stream_cancel_requested = True
            self.stream_thread.request_cancel()
        self.stream_controller.invalidate()
        self.stream_result = None
        if hasattr(self, "source_model"):
            self.source_model.set_stream_analysis(None)
        self._show_stream_summary()

    def _show_stream_summary(self) -> None:
        """恢复完整结果摘要，避免取消和失败留下进度文字。"""
        if not hasattr(self, "stream_status_label"):
            return
        if self.stream_result is not None and (
            self.stream_result.generation != self.stream_controller.generation
            or self.stream_result.dataset_id != (self.source_file or "live")
            or tuple(self.stream_result.packet_identity) != tuple(id(packet) for packet in self.packets)
        ):
            self.stream_result = None
            self.stream_controller.result = None
            self.source_model.set_stream_analysis(None)
        if self.stream_result is None:
            self.stream_status_label.setText("TCP流：尚未分析")
            return
        result = self.stream_result
        domains = {domain for flow in result.flows for domain in flow.domains}
        text = f"TCP流：{len(result.flows)} 条 · 可见域名 {len(domains)} 个 · 选中一行查看流详情"
        if result.warning:
            text += f"；{result.warning}"
        self.stream_status_label.setText(text)

    def _resize_stream_columns(self) -> None:
        """根据当前动态表头设置新增列宽，保留基础列宽。"""
        widths = {"域名": 190, "依据": 145, "TCP流": 80, "流方向": 90, "流状态": 140}
        for column, name in enumerate(self.source_model.HEADERS):
            if name in widths:
                self.packet_table.setColumnWidth(column, widths[name])

    def finish_stream_analysis(self) -> None:
        """线程退出后提交有效结果，或恢复此前的完整结果。"""
        worker = self.stream_thread
        if worker is None or not worker.isFinished():
            return
        self.stream_thread = None
        cancelled = (
            self._stream_cancel_requested or worker.cancelled or worker.cancel_event.is_set()
        )
        if cancelled or self._closing:
            self.state = "stopped"
            self.notice = "TCP 流分析已取消，原始数据保持不变"
        elif worker.error:
            self.state = "error"
            self.notice = worker.error
        elif worker.result is None:
            self.state = "error"
            self.notice = "TCP 流分析未返回完整结果"
        elif self.stream_controller.commit(
            worker.snapshot, worker.result, self.packets, self.source_file or "live"
        ):
            self.stream_result = worker.result
            self.source_model.set_stream_analysis(worker.result)
            self._resize_stream_columns()
            self.state = "stopped"
            self.notice = "TCP 流分析完成；选中一行查看跨包证据与缺口、冲突说明"
        else:
            self.state = "stopped"
            self.notice = "TCP 流分析结果已过期，未提交到当前数据集"
        self._stream_cancel_requested = False
        self._show_stream_summary()
        worker.deleteLater()
        self.update_controls()
        self.update_status()
