"""实验 1A 第五阶段：抓包、域名证据与 TCP 流重组窗口。"""
from __future__ import annotations
import sys
import time
from pathlib import Path
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QMessageBox
from scapy.all import conf
from capture_engine import CaptureWorker, PacketBuffer, SaveWorker
from packet_filter import FilterSpec
from packet_model import PacketTableModel
from domain_analysis import DomainAnalysisWorker
from domain_ui import DomainController
from stream_ui import StreamController, StreamWindowMixin
from window_presentation import WindowPresentationMixin
from pcap_io import LoadWorker as _LoadWorker
from sniffer_cli import get_interfaces
from ui_layout import apply_style, build_layout
LoadWorker = _LoadWorker
class SnifferWindow(WindowPresentationMixin, StreamWindowMixin, QMainWindow):
    """通过明确状态协调抓包、排空、保存及异步关闭。"""
    def __init__(self):
        """建立默认保留 1000 包的窗口，并启动批量消费定时器。"""
        super().__init__()
        self.buffer = PacketBuffer(max_packets=1000)
        self.capture_thread = None
        self.save_thread = None
        self.load_thread = None
        self.analysis_thread = None
        self.stream_thread = None
        self.stream_controller = StreamController()
        self.stream_result = None
        self._stream_cancel_requested = False
        self.domain_controller = DomainController()
        self.analysis_result = None
        self._dataset_generation = self.domain_controller.generation
        self._load_path = ""
        self._before_load = None
        self._load_cancel_requested = False
        self.source_file = ""
        self.filter_spec = FilterSpec()
        self.state = "stopped"
        self.notice = "选择网卡后开始抓包"
        self._closing = False
        self._stop_started = 0.0
        self._save_path = ""
        self._capture_interface = ""
        self.setWindowTitle("实验 1A · 网络嗅探器 · 第五阶段")
        self.resize(1240, 780)
        self.setMinimumSize(960, 640)
        build_layout(self)
        self.load_interfaces()
        self.packet_timer = QTimer(self)
        self.packet_timer.timeout.connect(self.flush_pending_packets)
        self.packet_timer.start(100)
        self.update_controls()
        self.update_status()
    def load_interfaces(self) -> None:
        if (self.is_busy() or self._closing or self.source_file
                or self.buffer.snapshot().received or self.packets):
            return
        self.interface_box.clear()
        try:
            default = str(getattr(conf.iface, "network_name", conf.iface))
            loopback = str(getattr(conf.loopback_name, "network_name", conf.loopback_name))
            default_index = -1
            for interface in get_interfaces():
                device = str(getattr(interface, "network_name", "") or getattr(interface, "name", ""))
                if not device:
                    continue
                name = str(getattr(interface, "name", "") or device)
                address = str(getattr(interface, "ip", "") or "无 IPv4 地址")
                marks = []
                if default in (device, name):
                    marks.append("默认建议")
                    default_index = self.interface_box.count()
                if loopback in (device, name):
                    marks.append("回环")
                prefix = f"[{' · '.join(marks)}] " if marks else ""
                self.interface_box.addItem(f"{prefix}{name} | IPv4: {address}", device)
                description = str(getattr(interface, "description", "") or name)
                self.interface_box.setItemData(
                    self.interface_box.count() - 1,
                    f"{description}\n设备标识：{device}", Qt.ItemDataRole.ToolTipRole,
                )
            if default_index >= 0:
                self.interface_box.setCurrentIndex(default_index)
            if not self.interface_box.count():
                self.state = "error"
                self.notice = "没有发现网卡，请检查 Npcap 安装和网卡状态"
        except Exception as exc:
            self.state = "error"
            self.notice = f"读取网卡失败：{exc}"
        self.update_controls()
        self.update_status()

    def change_limit(self) -> None:
        stats = self.buffer.snapshot()
        if self.is_busy() or self._closing or self.packets or stats.received or stats.pending:
            previous = self.limit_box.blockSignals(True)
            self.limit_box.setValue(self.buffer.max_packets)
            self.limit_box.blockSignals(previous)
            return
        self.buffer = PacketBuffer(max_packets=self.limit_box.value())
        self.update_controls()
        self.update_status()
    def start_capture(self) -> None:
        """启动抓包；停止后可在同一网卡继续累计到当前数据集。"""
        stats = self.buffer.snapshot()
        if self.is_busy() or self._closing or stats.pending:
            return
        if stats.limit_reached:
            self.notice = "已达到保留上限，请先保存并清空"
            self.update_status()
            return
        if self.source_file:
            self.notice = "当前为文件模式；请先清空数据后再开始实时抓包"
            self.update_status()
            return
        interface = self.interface_box.currentData()
        if not interface:
            self.notice = "请选择可用网卡"
            self.update_status()
            return
        if self.packets and self._capture_interface != str(interface):
            self.notice = "已有数据只能在原网卡继续抓包；更换网卡前请先清空"
            self.update_status()
            return
        self._capture_interface = str(interface)
        self.capture_thread = CaptureWorker(self._capture_interface, self.buffer)
        self.capture_thread.ready.connect(self._capture_ready)
        self.state = "starting"
        self.notice = "正在建立后台捕获任务"
        self.capture_thread.start()
        self._invalidate_analysis()
        self._invalidate_stream_analysis()
        self.update_controls()
        self.update_status()
    def _capture_ready(self) -> None:
        """仅接受当前任务在等待启动阶段发出的就绪信号。"""
        if self.sender() is self.capture_thread and self.state == "starting":
            self.state = "running"
            self.notice = "停止后可继续累计，或保存为 pcap 文件"
            self.update_controls()
            self.update_status()
    def stop_capture(self) -> None:
        """异步请求停止，继续处理事件与待显示数据。"""
        if self.stream_thread is not None:
            self._stream_cancel_requested = True
            self.stream_thread.request_cancel()
            self.state = "stream_cancel"
            self.notice = "正在取消 TCP 流分析，等待后台退出"
            self.update_controls()
            self.update_status()
            return
        if self.load_thread is not None:
            self._load_cancel_requested = True
            self.load_thread.request_cancel()
            self.state = "loading_cancel"
            self.notice = "正在取消读取，当前数据保持不变"
            self.update_controls()
            self.update_status()
            return
        if self.analysis_thread is not None:
            self.analysis_thread.request_cancel()
            self.state = "analysis_cancel"
            self.notice = "正在取消域名分析，当前原始数据保持不变"
            self.update_controls()
            self.update_status()
            return
        worker = self.capture_thread
        if worker is None:
            return
        worker.request_stop()
        if self.state not in ("stopping", "draining"):
            self._stop_started = time.monotonic()
        self.state = "draining" if worker.isFinished() else "stopping"
        self.notice = "等待后台退出并处理剩余数据"
        self.update_controls()
        self.update_status()
    def flush_pending_packets(self) -> None:
        """每次最多显示 250 包，后台退出且队列排空后才释放引用。"""
        batch = self.buffer.take_batch(250)
        if batch and (self.stream_thread is not None or self.stream_result is not None):
            self._invalidate_stream_analysis()
        self.source_model.append_batch(batch)
        if self.stream_result is not None and (
            self.source_model.stream_result is not self.stream_result
            or self.stream_result.dataset_id != (self.source_file or "live")
        ):
            self._invalidate_stream_analysis()
        worker = self.capture_thread
        if worker is not None:
            stats = self.buffer.snapshot()
            if worker.isFinished():
                if stats.pending:
                    self.state = "draining"
                    self.notice = "后台已退出，正在整理待处理包"
                else:
                    self.capture_thread = None
                    self.state = "error" if worker.error else "stopped"
                    self.notice = (
                        f"抓包失败：{worker.error}" if worker.error else
                        "达到保留上限，已自动停止；请保存后清空" if stats.limit_reached else
                        "后台已退出，待处理为零"
                    )
                    worker.deleteLater()
            elif stats.limit_reached and self.state in ("starting", "running"):
                self.stop_capture()
        elif self.state == "draining" and not self.buffer.snapshot().pending:
            self.state = "stopped"
            self.notice = "待处理数据已整理完毕"
        if self.save_thread is not None and self.save_thread.isFinished():
            self.finish_save()
        if self.load_thread is not None and self.load_thread.isFinished():
            self.finish_load()
        if self.analysis_thread is not None and self.analysis_thread.isFinished():
            self.finish_domain_analysis()
        if self.stream_thread is not None:
            if self.stream_thread.isFinished():
                self.finish_stream_analysis()
            elif not self._stream_cancel_requested:
                self.stream_status_label.setText(
                    f"TCP流：正在分析 {self.stream_thread.progress}%"
                )
        self.update_controls()
        self.update_status()
        if self._closing and not self.is_busy() and not self.buffer.snapshot().pending:
            self.close()
    def open_capture(self) -> None:
        """选择经典 PCAP 文件；已有数据时先确认替换。"""
        if self.is_busy() or self._closing:
            return
        path, _selected_filter = QFileDialog.getOpenFileName(
            self, "打开抓包文件", "", "PCAP 文件 (*.pcap);;所有文件 (*)"
        )
        if not path:
            return
        if self.packets or self.buffer.snapshot().received:
            answer = QMessageBox.question(
                self,
                "替换当前数据",
                "打开成功将替换当前数据，未保存不会自动保存。是否继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.open_path(path)
    def start_domain_analysis(self) -> None:
        """对停止后的稳定快照或已导入文件执行后台域名分析。"""
        if self.is_busy() or self._closing or self.buffer.snapshot().pending or not self.packets:
            return
        snapshot = self.domain_controller.snapshot(self.packets, self.source_file or "live")
        self._reset_analysis_stats()
        self.analysis_thread = DomainAnalysisWorker(snapshot, parent=self)
        self.state = "analysing"
        self.notice = "正在后台分析 DNS、HTTP Host 和 TLS SNI"
        self.analysis_thread.start()
        self.update_controls()
        self.update_status()
    analyze_domains = start_domain_analysis
    def _invalidate_analysis(self) -> None:
        """使旧分析结果失效；正在运行的 Worker 只请求取消。"""
        if self.analysis_thread is not None:
            self.analysis_thread.request_cancel()
        self._dataset_generation = self.domain_controller.invalidate()
        self.analysis_result = None
        self._reset_analysis_stats()
        if getattr(self.filter_spec, "domain", ""):
            self.filter_spec = FilterSpec(
                self.filter_spec.protocol, self.filter_spec.network, self.filter_spec.port
            )
            if hasattr(self, "domain_edit"):
                self.domain_edit.clear()
            if hasattr(self, "filter_status"):
                self.filter_status.setText("未设置筛选条件")
        if hasattr(self, "source_model"):
            self.source_model.set_analysis(None)
            self.proxy_model.set_filters(self.filter_spec, None)
    def finish_domain_analysis(self) -> None:
        worker = self.analysis_thread
        if worker is None or not worker.isFinished():
            return
        self.analysis_thread = None
        if worker.result is not None and not worker.cancelled and not worker.error:
            snapshot = worker.snapshot
            same_dataset = self.domain_controller.accepts(snapshot, worker.result, self.packets)
            if same_dataset:
                self.analysis_result = worker.result
                self.domain_controller.commit(snapshot, worker.result, self.packets)
                self._show_analysis_stats(worker.result)
                self.source_model.set_analysis(worker.result)
                self._resize_stream_columns()
                self.proxy_model.set_filters(self.filter_spec, None)
                self.state = "stopped"
                self.notice = "域名分析完成；候选 DNS/IP/TTL 默认不参与确定筛选"
            else:
                self._reset_analysis_stats()
                self.state = "stopped"
                self.notice = "域名分析结果已过期，未提交到当前数据集"
        elif worker.cancelled:
            self._reset_analysis_stats()
            self.state = "stopped"
            self.notice = "域名分析已取消，原始数据保持不变"
        else:
            self._reset_analysis_stats()
            self.state = "error"
            self.notice = worker.error or "域名分析失败，原始数据保持不变"
        worker.deleteLater()
        self.update_controls()
        self.update_status()
    def open_path(self, path: str) -> None:
        """后台读取文件，成功前保持当前模型、缓存和筛选不变。"""
        if self.is_busy() or self._closing or self.buffer.snapshot().pending or not str(path):
            return
        self._load_path = str(path)
        self._load_cancel_requested = False
        self._before_load = {
            "model": self.source_model,
            "buffer": self.buffer,
            "source_file": self.source_file,
            "filter_spec": self.filter_spec,
            "domain_rows": self.proxy_model.domain_rows,
            "state": self.state,
            "notice": self.notice,
        }
        try:
            self.load_thread = LoadWorker(
                self._load_path,
                max_packets=self.buffer.max_packets,
                max_bytes=self.buffer.max_bytes,
            )
            self.state = "loading"
            self.notice = "正在后台读取文件，当前数据保持不变"
            self.load_thread.start()
        except Exception as exc:
            self.load_thread = None
            self._load_path, self._load_cancel_requested = "", False
            self.notice = f"读取失败，当前数据未改变：{exc}"
            self.state = self._before_load["state"]
            self._before_load = None
        self.update_controls()
        self.update_status()
    def finish_load(self) -> None:
        """发布成功的读取快照，失败或取消则恢复替换前状态。"""
        worker = self.load_thread
        if worker is None or not worker.isFinished():
            return
        before = self._before_load or {}
        self.load_thread = None
        cancelled = bool(getattr(worker, "cancelled", False) or self._load_cancel_requested)
        error = str(getattr(worker, "error", "") or "")
        if cancelled or error:
            self.source_model = before.get("model", self.source_model)
            self.buffer = before.get("buffer", self.buffer)
            self.source_file = before.get("source_file", self.source_file)
            self.filter_spec = before.get("filter_spec", self.filter_spec)
            self.proxy_model.setSourceModel(self.source_model)
            self.proxy_model.set_filters(self.filter_spec, before.get("domain_rows"))
            self.detail_text.clear()
            if cancelled:
                self.state = before.get("state", "stopped")
                self.notice = "读取已取消，当前数据保持不变"
            else:
                self.state = "error"
                self.notice = f"读取失败，当前数据未改变：{error}"
            worker.deleteLater()
            self._before_load = None
            self._load_path = ""
            self._load_cancel_requested = False
            self.update_controls()
            self.update_status()
            return
        packets = list(getattr(worker, "packets", ()) or ())
        old_model = self.source_model
        new_model = PacketTableModel(self)
        new_buffer = PacketBuffer(max_packets=self.buffer.max_packets, max_bytes=self.buffer.max_bytes)
        for packet in packets:
            new_buffer.offer(packet)
            new_model.append_batch(new_buffer.take_batch(1))
        self.source_model = new_model
        self.buffer = new_buffer
        self.proxy_model.setSourceModel(new_model)
        self.proxy_model.set_filters(self.filter_spec, None)
        self.detail_text.clear()
        self.source_file = self._load_path
        self._invalidate_analysis()
        self._invalidate_stream_analysis()
        self._capture_interface = ""
        self.state = "stopped"
        warning = str(getattr(worker, "warning", "") or "")
        self.notice = f"已打开 {Path(self.source_file).name}"
        if warning:
            self.notice += f"；{warning}（后续文件数据未读取或校验）"
        worker.deleteLater()
        old_model.deleteLater()
        self._before_load = None
        self._load_path = ""
        self._load_cancel_requested = False
        self.update_controls()
        self.update_status()
    def clear_packets(self) -> None:
        """仅在后台空闲且缓存排空后重置数据、详情及全部计数。"""
        if self.is_busy() or self._closing or self.buffer.snapshot().pending:
            return
        self.source_model.clear()
        self._invalidate_analysis()
        self._invalidate_stream_analysis()
        self.buffer = PacketBuffer(max_packets=self.limit_box.value())
        self.source_file = ""
        self.filter_spec = FilterSpec()
        self.proxy_model.set_filters(self.filter_spec, None)
        self.protocol_box.setCurrentText("全部")
        self.ip_edit.clear()
        self.port_edit.clear()
        self.domain_edit.clear()
        self.filter_status.setText("未设置筛选条件")
        self.detail_text.clear()
        self._capture_interface = ""
        self.state = "stopped"
        self.notice = "列表与计数已清空，可更换网卡或保留上限"
        self.update_controls()
        self.update_status()
    def save_capture(self) -> None:
        """通过默认 pcap 后缀的保存对话框选择实际目标文件。"""
        if self.is_busy() or self._closing or self.buffer.snapshot().pending or not self.packets:
            return
        dialog = QFileDialog(self, "保存抓包文件")
        dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        dialog.setNameFilter("PCAP 文件 (*.pcap)")
        dialog.setDefaultSuffix("pcap")
        dialog.selectFile("capture.pcap")
        if dialog.exec() == QFileDialog.DialogCode.Accepted and dialog.selectedFiles():
            self.save_to_path(dialog.selectedFiles()[0])
    def save_to_path(self, path: str) -> None:
        """后台保存稳定的元组快照，期间禁止启动、清空或修改设置。
        Args:
            path: 已由调用方确认的目标路径，原样使用，不追加或替换后缀。
        """
        if self.is_busy() or self._closing or self.buffer.snapshot().pending or not self.packets:
            return
        path = str(path)
        if not path:
            return
        self._save_path = path
        self.save_thread = SaveWorker(self._save_path, tuple(self.packets))
        self.state = "saving"
        self.notice = "正在写入抓包文件，请稍候"
        self.save_thread.start()
        self.update_controls()
        self.update_status()
    def finish_save(self) -> None:
        """仅回收已退出的保存线程，失败时保留数据并取消关闭。"""
        worker = self.save_thread
        if worker is None or not worker.isFinished():
            return
        self.save_thread = None
        self.state = "error" if worker.error else "stopped"
        if worker.error:
            self._closing = False
        self.notice = (
            f"保存失败，数据仍保留：{worker.error}" if worker.error else
            f"已保存 {len(worker.packets)} 个数据包：{self._save_path}"
        )
        worker.deleteLater()
        self.update_controls()
        self.update_status()
    def closeEvent(self, event) -> None:
        """异步等待线程与缓存完成，避免阻塞窗口或销毁活动线程。"""
        if self.is_busy() or self.buffer.snapshot().pending:
            event.ignore()
            self._closing = True
            if self.load_thread is not None:
                self.stop_capture()
            elif self.capture_thread is not None:
                self.stop_capture()
            elif self.analysis_thread is not None:
                self.stop_capture()
            elif self.stream_thread is not None:
                self.stop_capture()
            elif self.save_thread is None:
                self.state = "draining"
                self.notice = "正在整理待处理包"
            self.update_controls()
            self.update_status()
            return
        self.packet_timer.stop()
        event.accept()
def main() -> int:
    """创建应用并启动阶段 5 桌面界面。"""
    app = QApplication(sys.argv)
    apply_style(app)
    window = SnifferWindow()
    window.show()
    return app.exec()
if __name__ == "__main__":
    raise SystemExit(main())
