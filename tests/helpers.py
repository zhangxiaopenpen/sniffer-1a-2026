"""无网络抓包线程替身及可供 GUI 测试复用的 Qt 辅助函数。"""

import os
import time
from threading import Event, Thread

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

_application = None


def app():
    """取得测试 QApplication，并保留引用以避免提前析构。

    Returns:
        当前进程唯一的 QApplication。
    """
    global _application
    _application = QApplication.instance() or QApplication([])
    return _application


def wait_until(predicate, timeout=3):
    """处理 Qt 事件，直到条件满足或超时。

    Args:
        predicate: 不接收参数的条件函数。
        timeout: 最长等待秒数。

    Returns:
        最后一次检查时条件是否满足。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        QTest.qWait(10)
    return bool(predicate())


class SnifferFactory:
    """创建真实 Python 线程驱动的 AsyncSniffer 替身，不访问网卡。"""

    def __init__(self, packets=(), delay=0, failure="", stop_delay=0, end=False):
        """配置替身产生的包、启动延迟、错误和退出行为。

        Args:
            packets: 按顺序送入 prn 回调的包序列。
            delay: 发出 ready 前的延迟秒数。
            failure: 非空时在启动阶段产生的错误文本。
            stop_delay: 收到停止请求后退出线程前的延迟秒数。
            end: 是否发完包便退出，不等待停止请求。
        """
        self.packets = packets
        self.delay = delay
        self.failure = failure
        self.stop_delay = stop_delay
        self.end = end
        self.instances = []

    def __call__(self, **kwargs):
        """保存全部构造参数，供抓包配置断言使用。"""
        sniffer = FakeSniffer(self, kwargs)
        self.instances.append(sniffer)
        return sniffer


class FakeSniffer:
    """模拟启动、回调、空闲和停止，保留 AsyncSniffer 的异常接口。"""

    def __init__(self, factory, kwargs):
        """保存工厂配置并初始化可观察的线程状态。"""
        self.factory = factory
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.exception = None
        self.stop_calls = 0
        self.ready = Event()
        self.stop_event = Event()

    def start(self):
        """启动仅运行内存回调的生产者线程。"""
        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        """按工厂配置产生回调，并记录供 join 重抛的异常。"""
        try:
            time.sleep(self.factory.delay)
            if self.factory.failure:
                raise OSError(self.factory.failure)
            self.running = True
            self.ready.set()
            self.kwargs["started_callback"]()
            for packet in self.factory.packets:
                if self.stop_event.is_set():
                    break
                self.kwargs["prn"](packet)
            if not self.factory.end:
                self.stop_event.wait(5)
            time.sleep(self.factory.stop_delay)
        except Exception as exc:
            self.exception = exc
        finally:
            self.running = False

    def stop(self, join=True):
        """记录停止请求；ready 前调用属于被测代码错误。"""
        if not self.ready.is_set():
            raise AssertionError("stop called before ready")
        self.stop_calls += 1
        self.stop_event.set()
        if join:
            self.join()

    def join(self, timeout=None):
        """等待线程结束，并模拟 Scapy 传播后台异常。"""
        self.thread.join(timeout)
        if self.exception is not None:
            raise self.exception
