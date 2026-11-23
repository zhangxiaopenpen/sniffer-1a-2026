"""严格、流式且有上限的经典 PCAP 后台载入。"""

from __future__ import annotations

import os
import stat
import struct
from threading import Event

from PySide6.QtCore import QThread
from scapy.all import conf
from scapy.utils import EDecimal

from capture_engine import MAX_BYTES, MAX_PACKETS


MAX_RECORD_BYTES = 1024 * 1024

# 经典 PCAP 的 magic 既决定字节序，也决定记录时间戳小数的单位。
_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
}

# 保留旧模块公开名称，便于调用方检查支持的四种 magic。
PCAP_MAGICS = _MAGICS


class _LoadCancelled(Exception):
    """载入任务被主动取消。"""


class LoadWorker(QThread):
    """在后台读取经典 PCAP，并在成功时一次性发布完整包列表。"""

    def __init__(
        self,
        path: str,
        max_packets: int = MAX_PACKETS,
        max_bytes: int = MAX_BYTES,
    ) -> None:
        """创建载入任务。

        Args:
            path: 本地经典 PCAP 路径。
            max_packets: 本次最多载入的数据包数量。
            max_bytes: 本次最多载入的捕获字节数。
        """
        super().__init__()
        if min(max_packets, max_bytes) <= 0:
            raise ValueError("载入上限必须为正数")
        self.path = str(path)
        self.max_packets = int(max_packets)
        self.max_bytes = int(max_bytes)

        # 所有公开结果字段都只在 run() 成功完成后写入；异常路径在 finally 清空。
        self.error = ""
        self.packets = []
        self.cancelled = False
        self.limited = False
        self.loaded_bytes = 0
        self.warning = ""
        self.linktype = None
        self._cancel_requested = Event()

    def request_cancel(self) -> None:
        """请求取消；实际清理在载入线程中完成。"""
        self._cancel_requested.set()

    def _check_cancel(self) -> None:
        """在文件读取、解码和结果发布前检查取消请求。"""
        if self._cancel_requested.is_set():
            raise _LoadCancelled

    def _read_global_header(self, source):
        """读取并校验 24 字节经典 PCAP 全局头。"""
        header = source.read(24)
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise ValueError("本阶段暂不支持 PCAPNG，请先另存为经典 PCAP")
        if len(header) != 24:
            raise ValueError("PCAP 文件头不完整，需要 24 字节")
        magic_info = _MAGICS.get(header[:4])
        if magic_info is None:
            raise ValueError("不是支持的经典 PCAP 文件：文件标识无效")

        endian, resolution = magic_info
        major, minor, _zone, _accuracy, snaplen, network = struct.unpack(
            endian + "HHIIII", header[4:]
        )
        if (major, minor) != (2, 4):
            raise ValueError(f"不支持 PCAP 版本 {major}.{minor}，需要 2.4")
        if snaplen == 0:
            raise ValueError("PCAP 文件头中的 snaplen 不能为 0")
        # 仅接受 Scapy 注册的原始链路类型；带 FCS 等附加标志的值会被拒绝。
        packet_class = conf.l2types.num2layer.get(network)
        if packet_class is None:
            raise ValueError(f"不支持 PCAP 链路类型或附加标志 {network}")
        self.linktype = network
        return endian, resolution, snaplen, packet_class

    def _read_records(self, source, endian, resolution, snaplen, packet_class):
        """逐条读取记录，超过预算时停止于下一条包体之前。"""
        packets = []
        loaded_bytes = 0

        while True:
            self._check_cancel()
            record_header = source.read(16)
            if not record_header:
                return packets, loaded_bytes, False
            number = len(packets) + 1
            if len(record_header) != 16:
                raise ValueError(f"第 {number} 个数据包的记录头被截断")

            seconds, fraction, captured, original = struct.unpack(
                endian + "IIII", record_header
            )
            if fraction >= resolution:
                raise ValueError(f"第 {number} 个数据包的时间戳小数超出范围")
            if captured > snaplen or captured > original:
                raise ValueError(f"第 {number} 个数据包的捕获长度字段不合法")
            if captured > MAX_RECORD_BYTES:
                raise ValueError(f"第 {number} 个数据包超过单包 1 MiB 的载入限制")

            # 预算判断必须位于包体读取之前；后续包体不会被读取或校验。
            if len(packets) >= self.max_packets or loaded_bytes + captured > self.max_bytes:
                return packets, loaded_bytes, True

            self._check_cancel()
            raw = source.read(captured)
            if len(raw) != captured:
                raise ValueError(f"第 {number} 个数据包的内容被截断")
            self._check_cancel()
            try:
                packet = packet_class(raw)
                if bytes(packet) != raw:
                    raise ValueError("解码后原始字节不能完整保持")
            except Exception as exc:
                raise ValueError(f"第 {number} 个数据包解码失败：{exc}") from exc

            # EDecimal 避免纳秒时间戳经过 float 造成精度丢失。
            packet.time = EDecimal(seconds) + EDecimal(fraction) / EDecimal(resolution)
            packet.wirelen = original
            packets.append(packet)
            loaded_bytes += captured

    def _clear_result(self) -> None:
        """清除暂存结果，使取消或错误绝不发布半成品。"""
        self.packets = []
        self.loaded_bytes = 0
        self.limited = False
        self.warning = ""
        self.linktype = None

    def run(self) -> None:
        """执行校验和载入；成功时一次性设置 packets。"""
        try:
            self._check_cancel()
            with open(self.path, "rb") as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("请选择本地普通 PCAP 文件")

                header_info = self._read_global_header(source)
                packets, loaded_bytes, limited = self._read_records(source, *header_info)

                after = os.fstat(source.fileno())
                if (before.st_size, before.st_mtime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise ValueError("文件在载入期间发生变化，请待写入结束后重试")

            self._check_cancel()
            self.packets = packets
            self.loaded_bytes = loaded_bytes
            self.limited = limited
            if limited:
                self.warning = (
                    f"已达到载入上限，仅载入前 {len(packets)} 个数据包；"
                    "文件后续数据未载入、未校验"
                )
        except _LoadCancelled:
            self.cancelled = True
        except Exception as exc:
            if self._cancel_requested.is_set():
                self.cancelled = True
            else:
                self.error = str(exc) or type(exc).__name__
        finally:
            if self.cancelled or self.error:
                self._clear_result()
