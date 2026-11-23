"""CLI 行为测试：所有抓包入口均被替换，不访问真实网络设备。"""

import contextlib
import datetime
import io
from types import SimpleNamespace
import unittest
from unittest import mock

from scapy.all import Ether, IP, Raw, TCP

import sniffer_cli


class SnifferCliTests(unittest.TestCase):
    """验证参数、接口选择和抓包生命周期的外部行为。"""

    def setUp(self):
        """建立不依赖本机网卡与 Npcap 的接口配置。"""
        self.wifi = SimpleNamespace(
            name="Wi-Fi", description="Wireless adapter",
            network_name=r"\Device\NPF_WIFI", ip="192.0.2.10",
        )
        self.ethernet = SimpleNamespace(
            name="Ethernet", description="Wired adapter",
            network_name=r"\Device\NPF_ETHERNET", ip="192.0.2.20",
        )
        self.loopback = SimpleNamespace(
            name="Loopback", description="Loopback adapter",
            network_name=r"\Device\NPF_Loopback", ip="127.0.0.1",
        )
        self.interfaces = [self.ethernet, self.loopback, self.wifi]
        self.conf = SimpleNamespace(
            use_pcap=True,
            iface=self.wifi,
            loopback_name=self.loopback.network_name,
            ifaces=mock.Mock(),
        )
        self.conf.ifaces.values.return_value = [
            self.wifi, self.ethernet, self.loopback,
        ]
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(sniffer_cli, "conf", self.conf).start()

    def run_main(self, arguments, *, tty=False):
        """捕获 CLI 输出，并控制输入终端状态。"""
        stdout, stderr = io.StringIO(), io.StringIO()
        stdin = mock.Mock()
        stdin.isatty.return_value = tty
        with (
            mock.patch.object(sniffer_cli.sys, "stdin", stdin),
            mock.patch.object(sniffer_cli, "get_interfaces", return_value=self.interfaces),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = sniffer_cli.main(arguments)
        return result, stdout.getvalue() + stderr.getvalue()

    def test_parser_defaults(self):
        options = sniffer_cli.build_parser().parse_args([])
        self.assertEqual(options.count, 20)
        self.assertEqual(options.timeout, 30)

    def test_count_rejects_negative_or_noninteger_values(self):
        for value in ("-1", "1.5", "nan", "abc"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    sniffer_cli.build_parser().parse_args([f"--count={value}"])
                self.assertEqual(raised.exception.code, 2)

    def test_timeout_rejects_negative_or_nonfinite_values(self):
        for value in ("-0.1", "nan", "inf", "-inf", "abc"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    sniffer_cli.build_parser().parse_args([f"--timeout={value}"])
                self.assertEqual(raised.exception.code, 2)

    def test_zero_limits_are_valid(self):
        options = sniffer_cli.build_parser().parse_args(["--count", "0", "--timeout", "0"])
        self.assertEqual(options.count, 0)
        self.assertEqual(options.timeout, 0)

    def test_interface_enumeration_has_stable_order(self):
        self.assertEqual(sniffer_cli.get_interfaces(), self.interfaces)

    def test_interface_listing_contains_selection_details(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            sniffer_cli.print_interfaces(self.interfaces)
        rendered = output.getvalue()
        for interface in self.interfaces:
            for attribute in ("name", "description", "network_name", "ip"):
                self.assertIn(getattr(interface, attribute), rendered)

    def test_interface_number_and_exact_identifiers(self):
        for selector in ("3", self.wifi.name, self.wifi.description, self.wifi.network_name):
            with self.subTest(selector=selector):
                self.assertIs(sniffer_cli.select_interface(self.interfaces, selector), self.wifi)

    def test_loopback_alias_uses_scapy_loopback_configuration(self):
        self.assertIs(sniffer_cli.select_interface(self.interfaces, "loopback"), self.loopback)
        self.conf.loopback_name = self.loopback.name
        self.assertIs(sniffer_cli.select_interface(self.interfaces, "loopback"), self.loopback)

    def test_unknown_and_out_of_range_interfaces_are_rejected(self):
        for selector in ("0", "-1", "4", "missing", "Wi", ""):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                sniffer_cli.select_interface(self.interfaces, selector)
        with self.assertRaises(ValueError):
            sniffer_cli.select_interface([], "1")

    def test_ambiguous_interface_identifier_is_rejected(self):
        duplicate = SimpleNamespace(
            name="Second Wi-Fi", description=self.wifi.description,
            network_name=r"\Device\NPF_SECOND", ip="192.0.2.30",
        )
        with self.assertRaises(ValueError):
            sniffer_cli.select_interface([self.wifi, duplicate], self.wifi.description)

    def test_list_only_does_not_capture_or_prompt(self):
        with (
            mock.patch.object(sniffer_cli, "capture_packets") as capture,
            mock.patch("builtins.input", side_effect=AssertionError("不应等待输入")),
        ):
            result, output = self.run_main(["--list"])
        self.assertEqual(result, 0)
        self.assertIn(self.wifi.name, output)
        capture.assert_not_called()

    def test_noninteractive_missing_interface_fails_without_prompting(self):
        with (
            mock.patch.object(sniffer_cli, "capture_packets") as capture,
            mock.patch("builtins.input", side_effect=AssertionError("非 TTY 不应等待输入")),
        ):
            result, output = self.run_main([])
        self.assertNotEqual(result, 0)
        self.assertTrue(output.strip())
        capture.assert_not_called()

    def test_interactive_quit_exits_without_capturing(self):
        with (
            mock.patch.object(sniffer_cli, "capture_packets") as capture,
            mock.patch("builtins.input", return_value="q"),
        ):
            result, _ = self.run_main([], tty=True)
        self.assertEqual(result, 0)
        capture.assert_not_called()

    def test_interactive_enter_selects_configured_default(self):
        with (
            mock.patch.object(sniffer_cli, "capture_packets", return_value=0) as capture,
            mock.patch("builtins.input", return_value=""),
        ):
            result, _ = self.run_main([], tty=True)
        self.assertEqual(result, 0)
        capture.assert_called_once_with(self.wifi, 20, 30)

    def test_main_forwards_explicit_capture_limits(self):
        with mock.patch.object(sniffer_cli, "capture_packets", return_value=2) as capture:
            result, _ = self.run_main([
                "--iface", self.wifi.network_name, "--count", "2", "--timeout", "1.25",
            ])
        self.assertEqual(result, 0)
        capture.assert_called_once_with(self.wifi, 2, 1.25)

    def test_windows_missing_npcap_is_actionable_error(self):
        self.conf.use_pcap = False
        with (
            mock.patch.object(sniffer_cli.sys, "platform", "win32"),
            mock.patch.object(sniffer_cli, "capture_packets") as capture,
        ):
            result, output = self.run_main(["--iface", self.wifi.name])
        self.assertNotEqual(result, 0)
        self.assertIn("Npcap", output)
        self.assertNotIn("抓包已就绪", output)
        capture.assert_not_called()

    def test_capture_uses_selected_device_and_does_not_store_packets(self):
        output = io.StringIO()
        with mock.patch.object(sniffer_cli, "sniff", return_value=[]) as sniff:
            with contextlib.redirect_stdout(output):
                received = sniffer_cli.capture_packets(self.wifi, 4, 1.25)
        self.assertEqual(received, 0)
        options = sniff.call_args.kwargs
        self.assertEqual(options["iface"], self.wifi.network_name)
        self.assertEqual(options["count"], 4)
        self.assertEqual(options["timeout"], 1.25)
        self.assertIs(options["store"], False)
        self.assertIs(options["promisc"], False)
        self.assertTrue(callable(options["prn"]))
        self.assertTrue(callable(options["started_callback"]))
        self.assertNotIn("抓包已就绪", output.getvalue())

    def test_unlimited_capture_converts_zero_timeout_to_none(self):
        with mock.patch.object(sniffer_cli, "sniff", return_value=[]) as sniff:
            with contextlib.redirect_stdout(io.StringIO()):
                sniffer_cli.capture_packets(self.wifi, 0, 0)
        self.assertEqual(sniff.call_args.kwargs["count"], 0)
        self.assertIsNone(sniff.call_args.kwargs["timeout"])

    def test_actual_scapy_packets_are_rendered_and_counted(self):
        packets = [
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=443) / Raw(b"one"),
            Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:04")
            / IP(src="192.0.2.3", dst="192.0.2.4") / TCP(dport=80) / Raw(b"two-two"),
        ]
        for offset, packet in enumerate(packets):
            packet.time = 1_700_000_000.125 + offset
        output = io.StringIO()

        def simulate_packets(**options):
            """按 Scapy 回调时序传递真实构造的数据包。"""
            self.assertNotIn("抓包已就绪", output.getvalue())
            options["started_callback"]()
            self.assertIn("抓包已就绪", output.getvalue())
            for packet in packets:
                options["prn"](packet)
            return []

        with mock.patch.object(sniffer_cli, "sniff", side_effect=simulate_packets):
            with contextlib.redirect_stdout(output):
                received = sniffer_cli.capture_packets(self.wifi, 2, 30)
        rendered = output.getvalue()
        self.assertEqual(received, 2)
        self.assertIn("本程序收到 2 个数据包。", rendered)
        for index, packet in enumerate(packets, start=1):
            self.assertIn(packet.summary(), rendered)
            self.assertIn(str(len(packet)), rendered)
            timestamp = datetime.datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")
            self.assertIn(timestamp, rendered)
            packet_line = next(line for line in rendered.splitlines() if packet.summary() in line)
            self.assertRegex(packet_line, rf"^#{index}\s")

    def test_no_traffic_timeout_is_successful_zero_packet_capture(self):
        def timeout_without_packets(**options):
            """模拟捕获器已打开但超时前未收到流量。"""
            options["started_callback"]()
            return []

        with mock.patch.object(sniffer_cli, "sniff", side_effect=timeout_without_packets):
            result, output = self.run_main(["--iface", "1", "--timeout", "0.1"])
        self.assertEqual(result, 0)
        self.assertIn("抓包已就绪", output)
        self.assertIn("本程序收到 0 个数据包。", output)

    def test_capture_open_error_never_reports_ready_or_success(self):
        with mock.patch.object(sniffer_cli, "sniff", side_effect=OSError("device unavailable")):
            result, output = self.run_main(["--iface", "1"])
        self.assertNotEqual(result, 0)
        self.assertIn("device unavailable", output)
        self.assertNotIn("抓包已就绪", output)

    def test_keyboard_interrupt_is_normal_stop_with_partial_count(self):
        packet = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=443)

        def interrupt_after_packet(**options):
            """模拟外层仍可能收到的 Ctrl+C。"""
            options["started_callback"]()
            options["prn"](packet)
            raise KeyboardInterrupt

        with mock.patch.object(sniffer_cli, "sniff", side_effect=interrupt_after_packet):
            result, output = self.run_main(["--iface", "1"])
        self.assertEqual(result, 0)
        self.assertIn("本程序收到 1 个数据包。", output)
        self.assertNotIn("Traceback", output)


if __name__ == "__main__":
    unittest.main()
