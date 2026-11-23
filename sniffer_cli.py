"""阶段 1：使用 Scapy 同步捕获并显示数据包摘要。"""

import argparse
from datetime import datetime
import math
import sys

_SCAPY_IMPORT_ERROR = None
try:
    from scapy.all import conf, sniff
except ImportError as error:
    conf = None
    sniff = None
    _SCAPY_IMPORT_ERROR = str(error)


def _nonnegative_int(value: str) -> int:
    """解析非负整数，拒绝小数和负数。"""
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("数量必须是非负整数（0 表示不限）") from error
    if number < 0:
        raise argparse.ArgumentTypeError("数量不能小于 0")
    return number


def _nonnegative_float(value: str) -> float:
    """解析有限的非负秒数。"""
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("超时必须是非负秒数（0 表示不限）") from error
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("超时必须是非负有限数，不能使用 NaN 或无穷大")
    return number


def build_parser() -> argparse.ArgumentParser:
    """建立中文命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        description="列出网卡并使用 Scapy/Npcap 捕获数据包，仅显示摘要。",
        epilog="数量和超时同时生效，以先达到者为准；两者均为 0 时按 Ctrl+C 停止。",
        add_help=False,
    )
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    parser.add_argument("--list", action="store_true", help="列出网卡后退出")
    parser.add_argument(
        "-i", "--iface", metavar="网卡",
        help="本次列表序号、精确名称/描述/设备标识，或 loopback 回环别名",
    )
    parser.add_argument(
        "-c", "--count", type=_nonnegative_int, default=20, metavar="数量",
        help="最多捕获的数据包数，默认 20；0 表示不限数量",
    )
    parser.add_argument(
        "-t", "--timeout", type=_nonnegative_float, default=30.0, metavar="秒",
        help="最多等待的秒数，默认 30；0 表示不限等待",
    )
    return parser


def get_interfaces() -> list:
    """获取按名称和设备标识排序的 Scapy 网卡对象列表。"""
    return sorted(
        conf.ifaces.values(),
        key=lambda interface: (
            str(interface.name).casefold(),
            str(interface.network_name).casefold(),
        ),
    )


def _default_network_name() -> str:
    """读取 Scapy 当前默认网卡的设备标识。"""
    return str(getattr(conf.iface, "network_name", conf.iface))


def _is_loopback(interface) -> bool:
    """判断接口是否对应 Scapy 的回环设备配置。"""
    loopback = str(getattr(conf.loopback_name, "network_name", conf.loopback_name))
    return loopback in (interface.name, interface.network_name)


def print_interfaces(interfaces) -> None:
    """显示网卡编号、地址及默认与回环标记。

    Args:
        interfaces: 本次选择使用的网卡对象列表。
    """
    print("序号\t名称\t描述\tIPv4\t标记")
    default_name = _default_network_name()
    for index, interface in enumerate(interfaces, start=1):
        marks = []
        if interface.network_name == default_name:
            marks.append("默认建议")
        if _is_loopback(interface):
            marks.append("回环")
        print(
            f"{index}\t{interface.name}\t{interface.description or '-'}\t"
            f"{interface.ip or '-'}\t{'、'.join(marks) or '-'}"
        )
        print(f"    设备标识：{interface.network_name}")
    if not interfaces:
        print("未发现可用网卡。")
    print("序号只对应本次列表；自动化调用建议使用精确设备标识或 loopback。")


def select_interface(interfaces, selector):
    """根据序号、精确字段或回环别名选择唯一网卡。

    Args:
        interfaces: 本次枚举的网卡对象列表。
        selector: 网卡序号、精确名称/描述/设备标识或 loopback。

    Returns:
        唯一匹配的原始网卡对象。

    Raises:
        ValueError: 选择为空、越界、未匹配或存在歧义。
    """
    value = str(selector).strip()
    if not value:
        raise ValueError("网卡选择不能为空，请先使用 --list 查看网卡")
    if value.isdecimal():
        index = int(value)
        if 1 <= index <= len(interfaces):
            return interfaces[index - 1]
        raise ValueError(f"网卡序号 {value} 越界，本次列表共有 {len(interfaces)} 项")
    if value.casefold() == "loopback":
        matches = [interface for interface in interfaces if _is_loopback(interface)]
    else:
        matches = [
            interface for interface in interfaces
            if value in (interface.name, interface.description, interface.network_name)
        ]
    if not matches:
        raise ValueError(f"未找到网卡 {value!r}，请使用 --list 查看并提供精确名称或设备标识")
    if len(matches) > 1:
        raise ValueError(f"网卡选择 {value!r} 存在歧义，请使用本次列表序号或唯一设备标识")
    return matches[0]


def capture_packets(interface, count: int, timeout: float) -> int:
    """同步抓包并输出摘要，不保留数据包列表。

    Args:
        interface: 已选择的 Scapy 网卡对象。
        count: 数量上限，0 表示不限。
        timeout: 等待秒数上限，0 表示不限。

    Returns:
        本程序实际收到的数据包数量。
    """
    received = 0

    def on_packet(packet):
        """输出单个包的时间、长度和摘要。"""
        nonlocal received
        received += 1
        timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
        print(f"#{received}  {timestamp}  {len(packet)} 字节  {packet.summary()}", flush=True)

    def on_started():
        """仅在 Scapy 成功打开接口后报告就绪。"""
        print(
            f"抓包已就绪：{interface.name}（{interface.network_name}）。按 Ctrl+C 停止。",
            flush=True,
        )

    try:
        sniff(
            iface=interface.network_name,
            store=False,
            promisc=False,
            count=count,
            timeout=None if timeout == 0 else timeout,
            prn=on_packet,
            started_callback=on_started,
        )
    except KeyboardInterrupt:
        # Scapy 默认在捕获循环中处理 Ctrl+C；此处涵盖启动和输出阶段。
        print("\n已停止抓包。", flush=True)
    finally:
        print(f"本程序收到 {received} 个数据包。", flush=True)
    return received


def main(argv=None) -> int:
    """执行命令行入口，正常停止返回 0，运行错误返回 1。

    Args:
        argv: 参数列表；None 表示读取当前进程参数。

    Returns:
        进程退出状态；参数语法错误由 argparse 以状态 2 退出。
    """
    args = build_parser().parse_args(argv)
    try:
        if _SCAPY_IMPORT_ERROR is not None:
            print(
                f"错误：无法导入 Scapy：{_SCAPY_IMPORT_ERROR}\n"
                "请在当前 Python 环境运行：python -X utf8 -m pip install -r requirements.txt",
                file=sys.stderr,
            )
            return 1
        if sys.platform == "win32" and not conf.use_pcap:
            print(
                "错误：Scapy 未启用 pcap，无法使用 Npcap 抓包。\n"
                "请从 https://npcap.com/ 安装 Npcap，启用 WinPcap API 兼容选项后重试；"
                "已安装时请检查 Npcap 服务，若限制为管理员访问，请以管理员身份运行。",
                file=sys.stderr,
            )
            return 1
        interfaces = get_interfaces()
        if args.list:
            print_interfaces(interfaces)
            return 0
        if not interfaces:
            raise ValueError("未发现网卡，请检查网卡状态及 Npcap 驱动")
        if args.iface is not None:
            interface = select_interface(interfaces, args.iface)
        else:
            if not sys.stdin.isatty():
                raise ValueError("非交互环境必须提供 --iface，例如 --iface loopback；使用 --list 查看网卡")
            print_interfaces(interfaces)
            default_name = _default_network_name()
            has_default = any(item.network_name == default_name for item in interfaces)
            default_hint = "，回车选择默认建议" if has_default else ""
            while True:
                value = input(f"请选择网卡序号/精确名称/设备标识{default_hint}，q 退出：").strip()
                if value.casefold() == "q":
                    print("已取消抓包。")
                    return 0
                if not value and has_default:
                    value = default_name
                try:
                    interface = select_interface(interfaces, value)
                    break
                except ValueError as error:
                    print(f"网卡选择无效：{error}")
        capture_packets(interface, args.count, args.timeout)
        return 0
    except KeyboardInterrupt:
        print("\n已停止，本次操作取消。")
        return 0
    except EOFError:
        print("错误：标准输入已结束，请使用 --iface 明确指定网卡。", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"错误：{type(error).__name__}: {error}", file=sys.stderr)
        print(
            "请用 --list 核对网卡及设备标识；若无法打开接口，请检查抓包权限、"
            "Npcap 安装和服务状态，必要时以管理员身份运行。",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
