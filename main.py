"""实验 1A 第二阶段：有界缓存、批量显示及异步抓包窗口。"""

from __future__ import annotations

import sys
import time

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow
from scapy.all import conf

from capture_engine import MAX_BYTES, CaptureWorker, PacketBuffer, SaveWorker
from sniffer_cli import get_interfaces
from ui_layout import apply_style, build_layout


class SnifferWindow(QMainWindow):
    """通过明确状态协调抓包、排空、保存及异步关闭。"""

    def __init__(self):
        """建立默认保留 1000 包的窗口，并启动批量消费定时器。"""
        super().__init__()
        self.buffer = PacketBuffer(max_packets=1000)
        self.capture_thread = None
        self.save_thread = None
        self.state = "stopped"
        self.notice = "选择网卡后开始抓包"
        self._closing = False
        self._stop_started = 0.0
        self._save_path = ""
        self._capture_interface = ""
        self.setWindowTitle("实验 1A · 网络嗅探器 · 第二阶段")
        self.resize(1240, 780)
        self.setMinimumSize(960, 640)
        build_layout(self)
        self.load_interfaces()
        self.packet_timer = QTimer(self)
        self.packet_timer.timeout.connect(self.flush_pending_packets)
        self.packet_timer.start(100)
        self.update_controls()
        self.update_status()

    @property
    def packets(self):
        """返回按捕获顺序保留在表格模型中的数据包。"""
        return self.packet_model.packets

    def load_interfaces(self) -> None:
        """列出接口名称及 IPv4，标记默认建议与回环接口。"""
        if self.is_busy() or self._closing or self.buffer.snapshot().received or self.packets:
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

    def is_busy(self) -> bool:
        """线程退出但尚未排空时，保留线程引用并继续视为忙。"""
        return self.capture_thread is not None or self.save_thread is not None

    def update_controls(self) -> None:
        """锁定与当前后台任务或既有数据冲突的操作。"""
        stats = self.buffer.snapshot()
        idle = not self.is_busy() and not self._closing and stats.pending == 0
        empty = not self.packets and stats.received == 0
        self.start_button.setEnabled(
            idle and bool(self.interface_box.count()) and not stats.limit_reached
        )
        self.stop_button.setEnabled(
            self.capture_thread is not None
            and self.state in ("starting", "running") and not self._closing
        )
        self.clear_button.setEnabled(idle)
        self.save_button.setEnabled(idle and bool(self.packets))
        self.interface_box.setEnabled(idle and empty)
        self.limit_box.setEnabled(idle and empty)

    def update_status(self) -> None:
        """显示应用回调计数，不将应用丢弃解释为网卡总丢包。"""
        stats = self.buffer.snapshot()
        labels = {
            "starting": "正在打开网卡", "running": "正在抓包",
            "stopping": "正在停止抓包", "draining": "正在整理剩余数据",
            "stopped": "已停止", "saving": "正在保存", "error": "发生错误",
        }
        text = f"状态：{labels[self.state]}"
        if self.notice:
            text += f" · {self.notice}"
        if self._closing:
            text += " · 完成当前任务后自动关闭"
        if self.state == "stopping" and time.monotonic() - self._stop_started > 5:
            text += " · 正在等待驱动退出，窗口仍可响应"
        self.status_label.setText(text)
        self.status_label.setToolTip(text)
        self.counter_label.setText(
            f"收到 {stats.received} = 保留 {stats.accepted} + 应用丢弃 {stats.dropped}"
            f"  |  已显示 {len(self.packets)} · 待处理 {stats.pending}"
            f"  |  丢弃明细：缓存 {stats.drop_queue} / 上限 {stats.drop_limit}"
            f"  |  原始数据 {stats.retained_bytes / 1048576:.2f} / {MAX_BYTES / 1048576:.0f} MiB"
        )

    def change_limit(self) -> None:
        """仅在空闲且计数清空后修改保留上限。"""
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
        self.packet_model.append_batch(self.buffer.take_batch(250))
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
        self.update_controls()
        self.update_status()
        if self._closing and not self.is_busy() and not self.buffer.snapshot().pending:
            self.close()

    def show_selected_packet(self) -> None:
        """按稳定行号展示选中包的字段和捕获时的原始字节。"""
        rows = self.packet_table.selectionModel().selectedRows()
        if not rows:
            self.detail_text.clear()
            return
        row = rows[0].row()
        if not 0 <= row < len(self.packets):
            return
        packet = self.packets[row]
        try:
            original = getattr(packet, "original", None)
            raw = bytes(original) if original else bytes(packet)
            self.detail_text.setPlainText(
                f"{packet.show(dump=True)}\n\n十六进制原始数据：\n{raw.hex(' ')}"
            )
        except Exception as exc:
            self.detail_text.setPlainText(f"无法展示该数据包：{exc}")

    def clear_packets(self) -> None:
        """仅在后台空闲且缓存排空后重置数据、详情及全部计数。"""
        if self.is_busy() or self._closing or self.buffer.snapshot().pending:
            return
        self.packet_model.clear()
        self.buffer = PacketBuffer(max_packets=self.limit_box.value())
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
            if self.capture_thread is not None:
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
    """创建应用并启动第二阶段桌面界面。"""
    app = QApplication(sys.argv)
    apply_style(app)
    window = SnifferWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
