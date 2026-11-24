"""生成阶段 5 的离线 TCP 流教学数据，不发送任何网络流量。"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

HTTP_DOMAIN = "www.stage5.example.test"
TLS_DOMAIN = "tls.stage5.example.test"
BASE_TIME = 1_800_000_000
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"


def make_client_hello(hostname: str) -> bytes:
    """构造带一个明文 SNI 的完整 TLS ClientHello 记录。

    Args:
        hostname: ASCII 或可转为 IDNA 的教学域名。

    Returns:
        TLS 记录头、握手头和 ClientHello 的完整字节。
    """
    name = hostname.encode("idna")
    if not name or len(name) > 253:
        raise ValueError("教学 SNI 域名长度必须为 1～253 字节")
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    server_names = len(entry).to_bytes(2, "big") + entry
    extension = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    body = (
        b"\x03\x03" + bytes(range(32))  # TLS 1.2 与固定教学随机字段。
        + b"\x00"  # 空 session_id。
        + b"\x00\x02\xc0\x2f"  # 一个密码套件。
        + b"\x01\x00"  # 一个空压缩方法。
        + len(extension).to_bytes(2, "big") + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _packet(
    port: int, sequence: int, acknowledgement: int, flags: str,
    payload: bytes = b"", *, ipv6: bool = False, reverse: bool = False,
    server_port: int = 80,
) -> Packet:
    """构造校验和与长度字段完整的合成以太网 TCP 包。"""
    source, destination = (("2001:db8::10", "2001:db8::20") if ipv6
                           else ("192.0.2.10", "192.0.2.20"))
    source_mac, destination_mac = CLIENT_MAC, SERVER_MAC
    sport, dport = port, server_port
    if reverse:
        source, destination = destination, source
        source_mac, destination_mac = destination_mac, source_mac
        sport, dport = dport, sport
    network = IPv6(src=source, dst=destination) if ipv6 else IP(src=source, dst=destination)
    packet = Ether(src=source_mac, dst=destination_mac) / network / TCP(
        sport=sport, dport=dport, seq=sequence, ack=acknowledgement, flags=flags,
    )
    if payload:
        packet /= Raw(payload)
    return Ether(bytes(packet))


def _handshake(port: int, client: int, server: int, **options) -> list[Packet]:
    """返回规范的 SYN、SYN+ACK 和 ACK 三次握手。"""
    return [
        _packet(port, client, 0, "S", **options),
        _packet(port, server, client + 1, "SA", reverse=True, **options),
        _packet(port, client + 1, server + 1, "A", **options),
    ]


def _close(port: int, client_end: int, server: int, **options) -> list[Packet]:
    """返回双方 FIN 和最后 ACK，服务器没有应用层载荷。"""
    return [
        _packet(port, client_end, server + 1, "FA", **options),
        _packet(port, server + 1, client_end + 1, "FA", reverse=True, **options),
        _packet(port, client_end + 1, server + 2, "A", **options),
    ]


def build_demo_packets() -> list[Packet]:
    """创建五条独立 TCP 流，覆盖正常重组及三种不确定情况。

    Returns:
        固定顺序、固定时间戳的合成包列表；源端口 51001～51005 对应五种场景。
    """
    packets: list[Packet] = []
    request = (
        f"GET /stage5 HTTP/1.1\r\nHost: {HTTP_DOMAIN}\r\n"
        "User-Agent: Offline-Teaching-Demo\r\nConnection: close\r\n\r\n"
    ).encode("ascii")

    # 流 1：Host 名字中间拆段，尾段先到，并重复捕获头段。
    client, server, port = 1000, 9000, 51001
    cut = request.index(HTTP_DOMAIN.encode("ascii")) + 7
    packets.extend(_handshake(port, client, server))
    packets.extend([
        _packet(port, client + 1 + cut, server + 1, "PA", request[cut:]),
        _packet(port, client + 1, server + 1, "PA", request[:cut]),
        _packet(port, client + 1, server + 1, "PA", request[:cut]),
    ])
    packets.extend(_close(port, client + 1 + len(request), server))

    # 流 2：IPv6 ClientHello 拆成三段，SNI 名字也跨段。
    client, server, port = 2000, 10000, 51002
    hello = make_client_hello(TLS_DOMAIN)
    cuts = (0, 11, hello.index(TLS_DOMAIN.encode("ascii")) + 5, len(hello))
    options = {"ipv6": True, "server_port": 443}
    packets.extend(_handshake(port, client, server, **options))
    for start, end in zip(cuts, cuts[1:]):
        packets.append(_packet(port, client + 1 + start, server + 1,
                               "PA", hello[start:end], **options))
    packets.extend(_close(port, client + 1 + len(hello), server, **options))

    # 流 3：SYN 后空缺七个序号；后面的完整 HTTP 文本也不能作为确定证据。
    client, server, port = 3000, 11000, 51003
    packets.extend(_handshake(port, client, server))
    packets.append(_packet(port, client + 8, server + 1, "PA", request))
    packets.append(_packet(port, server + 1, client + 1, "RA", reverse=True))

    # 流 4：首次与再次捕获的重叠 Host 字节不同。
    client, server, port = 4000, 12000, 51004
    packets.extend(_handshake(port, client, server))
    packets.append(_packet(port, client + 1, server + 1, "PA", request))
    conflict_offset = request.index(HTTP_DOMAIN.encode("ascii"))
    packets.append(_packet(port, client + 1 + conflict_offset, server + 1, "PA", b"bad"))
    packets.append(_packet(port, server + 1, client + 1 + len(request), "RA", reverse=True))

    # 流 5：捕获从连接中途开始，只有完整 HTTP 字节而没有 SYN。
    client, server, port = 5000, 13000, 51005
    packets.append(_packet(port, client + 1, server + 1, "PA", request))
    packets.append(_packet(port, server + 1, client + 1 + len(request), "A", reverse=True))

    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index / 100
    return packets


def main(argv: list[str] | None = None) -> int:
    """写入离线 PCAP 并打印验收预期，默认拒绝覆盖同名文件。

    Args:
        argv: 可选命令行参数；None 表示读取实际命令行。

    Returns:
        成功为 0；文件已存在或不能写入为 1。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", type=Path,
                        default=Path(__file__).with_name("stage5_tcp_demo.pcap"))
    parser.add_argument("--force", action="store_true", help="明确允许覆盖已有输出文件")
    args = parser.parse_args(argv)
    packets = build_demo_packets()
    try:
        with args.output.open("wb" if args.force else "xb") as destination:
            wrpcap(destination, packets)
    except FileExistsError:
        print(f"文件已存在，未覆盖：{args.output}\n需要覆盖时加 --force，或用 --output 指定新文件。")
        return 1
    except OSError as exc:
        print(f"写入失败：{exc}")
        return 1
    print(f"已生成 {len(packets)} 个完全合成的离线数据包：{args.output.resolve()}")
    print("本脚本未发送网络数据。打开该 PCAP 后点击“追踪 TCP 流”。")
    print(f"源端口 51001：IPv4 HTTP 跨段、乱序与重传；预期 Host = {HTTP_DOMAIN}")
    print(f"源端口 51002：IPv6 TLS ClientHello 跨段；预期 SNI = {TLS_DOMAIN}")
    print("源端口 51003：SYN 后存在前导缺口；预期不产生确定域名证据。")
    print("源端口 51004：重叠字节冲突；预期不产生确定域名证据。")
    print("源端口 51005：未捕获 SYN、流起点未知；预期不产生确定域名证据。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
