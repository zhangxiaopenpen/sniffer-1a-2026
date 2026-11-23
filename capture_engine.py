"""有界抓包缓存及后台抓包、保存任务。"""

from __future__ import annotations

import os
import tempfile
from collections import deque
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from threading import Event, Lock

from PySide6.QtCore import QThread, Signal
from scapy.all import AsyncSniffer, conf
from scapy.utils import PcapWriter

MAX_PACKETS = 10_000
MAX_BYTES = 32 * 1024 * 1024
MAX_PENDING = 2_048
MAX_PENDING_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class BufferSnapshot:
    """某个时刻的计数；仅统计已进入应用回调的数据包。"""

    received: int
    accepted: int
    dropped: int
    pending: int
    retained_bytes: int
    limit_reached: bool
    drop_queue: int
    drop_limit: int


class PacketBuffer:
    """在生产端限制包数及原始字节数，供界面批量消费。

    accepted 包含已显示和待显示的包；取走队列中的包不释放总保留预算。
    原始字节预算不等同于 Python 进程的内存占用上限。
    """

    def __init__(
        self,
        max_packets: int = MAX_PACKETS,
        max_bytes: int = MAX_BYTES,
        max_pending: int = MAX_PENDING,
        max_pending_bytes: int = MAX_PENDING_BYTES,
    ) -> None:
        """创建缓存。

        Args:
            max_packets: 本轮数据集最多保留的包数。
            max_bytes: 本轮数据集最多保留的原始字节数。
            max_pending: 待显示队列的最大包数。
            max_pending_bytes: 待显示队列的最大原始字节数。
        """
        if min(max_packets, max_bytes, max_pending, max_pending_bytes) <= 0:
            raise ValueError("缓存上限必须为正数")
        self.max_packets = max_packets
        self.max_bytes = max_bytes
        self.max_pending = max_pending
        self.max_pending_bytes = max_pending_bytes
        self._lock = Lock()
        self._queue = deque()
        self._pending_bytes = 0
        self._received = 0
        self._accepted = 0
        self._retained_bytes = 0
        self._drop_queue = 0
        self._drop_limit = 0
        self._limit_reached = False

    def offer(self, packet) -> None:
        """接收一个包，超过缓存或保留预算时记账而不保留。

        Args:
            packet: Scapy Packet 对象。返回 None 以避免 prn 回调打印。
        """
        original = getattr(packet, "original", None)
        size = len(original) if original else len(packet)
        with self._lock:
            self._received += 1
            if (
                self._limit_reached
                or self._accepted >= self.max_packets
                or self._retained_bytes + size > self.max_bytes
            ):
                self._drop_limit += 1
                self._limit_reached = True
                return
            if (
                len(self._queue) >= self.max_pending
                or self._pending_bytes + size > self.max_pending_bytes
            ):
                self._drop_queue += 1
                return
            self._queue.append((packet, size))
            self._pending_bytes += size
            self._accepted += 1
            self._retained_bytes += size
            self._limit_reached = (
                self._accepted >= self.max_packets
                or self._retained_bytes >= self.max_bytes
            )

    def take_batch(self, max_count: int = 250) -> list:
        """取走最多指定数量的包，保留原有到达顺序。

        Args:
            max_count: 本次消费数量的上限。

        Returns:
            待添加到界面模型的包列表。
        """
        packets = []
        with self._lock:
            for _ in range(min(max(0, max_count), len(self._queue))):
                packet, size = self._queue.popleft()
                self._pending_bytes -= size
                packets.append(packet)
        return packets

    def snapshot(self) -> BufferSnapshot:
        """原子读取计数，满足 received = accepted + dropped。"""
        with self._lock:
            return BufferSnapshot(
                received=self._received,
                accepted=self._accepted,
                dropped=self._drop_queue + self._drop_limit,
                pending=len(self._queue),
                retained_bytes=self._retained_bytes,
                limit_reached=self._limit_reached,
                drop_queue=self._drop_queue,
                drop_limit=self._drop_limit,
            )


class CaptureWorker(QThread):
    """管理 Scapy 后台线程，不向 GUI 发送逐包信号。"""

    ready = Signal()

    def __init__(self, interface: str, buffer: PacketBuffer, sniffer_factory=AsyncSniffer):
        """创建抓包任务。

        Args:
            interface: Npcap 网卡标识。
            buffer: 本轮数据集共用的有界缓存。
            sniffer_factory: 默认创建 AsyncSniffer；测试可注入替身。
        """
        super().__init__()
        self.interface = interface
        self.buffer = buffer
        self.sniffer_factory = sniffer_factory
        self.error = ""
        self.stop_reason = ""
        self._stop_requested = Event()
        self._ready = Event()

    def request_stop(self) -> None:
        """记录停止请求，包括底层还未启动完成时的请求。"""
        self._stop_requested.set()

    def _on_ready(self) -> None:
        """底层停止控制通道已建立，可以安全发送停止请求。"""
        self._ready.set()
        self.ready.emit()

    def run(self) -> None:
        """等待底层真正退出后才结束 QThread，并保留最终错误。"""
        if self._stop_requested.is_set():
            self.stop_reason = "user"
            return
        if self.buffer.snapshot().limit_reached:
            self.stop_reason = "limit"
            return
        sniffer = None
        stop_sent = False
        try:
            sniffer = self.sniffer_factory(
                iface=self.interface,
                prn=self.buffer.offer,
                promisc=False,
                store=False,
                started_callback=self._on_ready,
            )
            sniffer.start()
            if sniffer.thread is None:
                raise RuntimeError("抓包线程未能启动")
            while sniffer.thread.is_alive():
                if self.buffer.snapshot().limit_reached:
                    self.stop_reason = "limit"
                    self._stop_requested.set()
                if self._stop_requested.is_set() and self._ready.is_set() and not stop_sent:
                    if sniffer.running:
                        try:
                            sniffer.stop(join=False)
                        except Exception:
                            # 正常退出和 stop() 之间存在竞态；仍存活则是真错误。
                            if sniffer.thread.is_alive():
                                raise
                    stop_sent = True
                sniffer.join(timeout=0.05)
            sniffer.join()
            if not self._stop_requested.is_set():
                raise RuntimeError("抓包意外结束，请检查网卡连接或 Npcap 状态")
            self.stop_reason = self.stop_reason or "user"
        except Exception as exc:
            self.error = str(exc) or type(exc).__name__
            self.stop_reason = "error"
        finally:
            # 出错也必须等生产者退出，否则窗口释放后仍可能出现回调。
            if sniffer is not None and sniffer.thread is not None:
                if sniffer.thread.is_alive() and self._ready.is_set() and sniffer.running:
                    try:
                        sniffer.stop(join=False)
                    except Exception as exc:
                        self.error = self.error or str(exc)
                        self.stop_reason = "error"
                sniffer.thread.join()


class SaveWorker(QThread):
    """将稳定快照写入临时文件，成功后原子替换目标文件。"""

    def __init__(self, path: str, packets):
        """创建保存任务。

        Args:
            path: 目标 pcap 路径。
            packets: 停止抓包并排空缓存后的包序列。
        """
        super().__init__()
        self.path = str(path)
        self.packets = tuple(packets)
        self.error = ""

    @staticmethod
    def _raw_packet(packet) -> bytes:
        """优先使用原始捕获字节，避免保存时重建报头。"""
        original = getattr(packet, "original", None)
        return bytes(original) if original else bytes(packet)

    def _write_snapshot(self, output) -> None:
        """以纳秒格式保存，并显式传入无浮点舍入的记录时间。

        Args:
            output: 同目录临时文件的二进制写入句柄。
        """
        linktypes = {conf.l2types.layer2num.get(type(packet)) for packet in self.packets}
        if None in linktypes:
            raise ValueError("无法确定数据包链路类型，不能安全保存为 PCAP")
        if len(linktypes) > 1:
            raise ValueError("经典 PCAP 不能保存混合链路类型的数据包")
        linktype = next(iter(linktypes), 1)
        snaplen = max((len(self._raw_packet(packet)) for packet in self.packets), default=65535)
        with PcapWriter(output, nano=True, snaplen=max(1, snaplen), linktype=linktype) as writer:
            # Scapy 构造器对 linktype=0 的判断为假，显式赋值保留合法 DLT_NULL。
            writer.linktype = linktype
            writer.write_header(None)
            for packet in self.packets:
                raw = self._raw_packet(packet)
                timestamp = Decimal(str(packet.time))
                if not timestamp.is_finite() or timestamp < 0:
                    raise ValueError("数据包时间戳不是有效的非负时间")
                sec, nanos = divmod(int(timestamp * 1_000_000_000), 1_000_000_000)
                if sec > 0xFFFFFFFF:
                    raise ValueError("数据包时间戳超出经典 PCAP 秒字段范围")
                wirelen = getattr(packet, "wirelen", None)
                wirelen = len(raw) if wirelen is None else int(wirelen)
                if not len(raw) <= wirelen <= 0xFFFFFFFF:
                    raise ValueError("数据包原始线路长度不合法")
                writer.write_packet(
                    raw, sec=sec, usec=nanos, caplen=len(raw), wirelen=wirelen
                )

    def run(self) -> None:
        """后台保存；失败时保留原目标和界面内的数据。"""
        temporary_path = None
        try:
            target = Path(self.path)
            descriptor, temporary_path = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            # 传文件对象可避开底层对 Windows 中文路径的额外处理。
            with os.fdopen(descriptor, "wb") as output:
                self._write_snapshot(output)
            os.replace(temporary_path, target)
            temporary_path = None
        except Exception as exc:
            self.error = str(exc) or type(exc).__name__
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass
