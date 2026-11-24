"""窗口呈现、显示筛选和详情操作，保持原始数据集与后台任务独立。"""

from __future__ import annotations

import time
from pathlib import Path

from capture_engine import MAX_BYTES
from packet_filter import FilterSpec, parse_filter


class WindowPresentationMixin:
    """提供数据展示与筛选方法，供主窗口协调任务时调用。"""

    @property
    def packets(self):
        """返回按捕获顺序保留在表格模型中的数据包。"""
        return self.source_model.packets

    @property
    def displayed_packets(self):
        """返回当前筛选后可见的数据包，保存始终使用 packets。"""
        return self.proxy_model.rowCount()

    def is_busy(self) -> bool:
        return (self.capture_thread is not None or self.save_thread is not None
                or self.load_thread is not None or self.analysis_thread is not None
                or self.stream_thread is not None)

    def update_controls(self) -> None:
        stats = self.buffer.snapshot()
        idle = not self.is_busy() and not self._closing and stats.pending == 0
        empty = not self.packets and stats.received == 0
        self.start_button.setEnabled(
            idle and not self.source_file and bool(self.interface_box.count())
            and not stats.limit_reached
        )
        loading = self.load_thread is not None
        analysing = self.analysis_thread is not None
        streaming = self.stream_thread is not None
        self.stop_button.setText(
            "取消读取" if loading else "取消流分析" if streaming else
            "取消分析" if analysing else "停止"
        )
        self.stop_button.setEnabled(
            ((loading and not self._load_cancel_requested)
             or (streaming and not self._stream_cancel_requested)
             or (analysing and not self.analysis_thread.cancel_event.is_set()) or (self.capture_thread is not None
                         and self.state in ("starting", "running")))
            and not self._closing
        )
        self.clear_button.setEnabled(idle)
        self.save_button.setEnabled(idle and bool(self.packets))
        self.open_button.setEnabled(idle)
        self.interface_box.setEnabled(idle and empty and not self.source_file)
        self.limit_box.setEnabled(idle and empty and not self.source_file)
        for widget in (self.protocol_box, self.ip_edit, self.port_edit,
                       self.domain_edit, self.candidate_box,
                       self.apply_filter_button, self.reset_filter_button):
            widget.setEnabled(idle)
        self.analyze_button.setEnabled(idle and bool(self.packets))
        self.stream_button.setEnabled(idle and bool(self.packets))

    def update_status(self) -> None:
        """显示应用回调计数，不将应用丢弃解释为网卡总丢包。"""
        stats = self.buffer.snapshot()
        labels = {
            "starting": "正在打开网卡", "running": "正在抓包",
            "stopping": "正在停止抓包", "draining": "正在整理剩余数据",
            "stopped": "已停止", "saving": "正在保存", "error": "发生错误",
            "loading": "正在读取 PCAP", "loading_cancel": "正在取消读取",
            "analysing": "正在分析域名", "analysis_cancel": "正在取消域名分析",
            "stream_analysing": "正在分析 TCP 流", "stream_cancel": "正在取消 TCP 流分析",
        }
        mode = f"文件模式：{Path(self.source_file).name}" if self.source_file else "实时模式"
        text = f"模式：{mode} · 状态：{labels.get(self.state, self.state)}"
        if self.notice:
            text += f" · {self.notice}"
        if self._closing:
            text += " · 完成当前任务后自动关闭"
        if self.state == "stopping" and time.monotonic() - self._stop_started > 5:
            text += " · 正在等待驱动退出，窗口仍可响应"
        self.status_label.setText(text)
        self.status_label.setToolTip(text)
        visible_text = (f"当前显示 {self.displayed_packets} / 保留 {stats.accepted}"
                        if self.displayed_packets else
                        (f"无匹配（0 / 保留 {stats.accepted}）" if self.packets
                         else "当前显示 0 / 保留 0"))
        self.counter_label.setText(
            f"收到 {stats.received} = 保留 {stats.accepted} + 应用丢弃 {stats.dropped}"
            f"  |  {visible_text}"
            f" · 待处理 {stats.pending}"
            f"  |  丢弃明细：缓存 {stats.drop_queue} / 上限 {stats.drop_limit}"
            f"  |  原始数据 {stats.retained_bytes / 1048576:.2f} / {MAX_BYTES / 1048576:.0f} MiB"
        )

    def _reset_analysis_stats(self) -> None:
        """清除当前数据集的 DNS 统计摘要。"""
        if hasattr(self, "analysis_stats_label"):
            self.analysis_stats_label.setText("DNS统计：尚未分析")

    def _show_analysis_stats(self, result) -> None:
        """显示完整分析结果的 DNS 统计，不受表格筛选影响。"""
        stats = getattr(result, "stats", None)
        if stats is None:
            self._reset_analysis_stats()
            return
        self.analysis_stats_label.setText(
            "DNS统计："
            f"查询 {getattr(stats, 'query_count', 0)} · "
            f"响应 {getattr(stats, 'response_count', 0)} · "
            f"匹配事务 {getattr(stats, 'matched_transaction_count', 0)} · "
            f"未匹配查询 {getattr(stats, 'unmatched_query_count', 0)} · "
            f"唯一直接域名 {getattr(stats, 'unique_domain_count', 0)}"
        )

    def show_selected_packet(self) -> None:
        """按稳定行号展示选中包的字段和捕获时的原始字节。"""
        rows = self.packet_table.selectionModel().selectedRows()
        if not rows:
            self.detail_text.clear()
            return
        source_index = self.proxy_model.mapToSource(rows[0])
        row = source_index.row()
        if not source_index.isValid() or not 0 <= row < len(self.packets):
            return
        packet = self.packets[row]
        try:
            original = getattr(packet, "original", None)
            raw = bytes(original) if original else bytes(packet)
            text = (
                f"{packet.show(dump=True)}\n\n十六进制原始数据：\n{raw.hex(' ')}"
            )
            if self.analysis_result is not None:
                detail = self.analysis_result.row_evidence(row)
                if detail:
                    source_labels = {
                        "dns_query": "DNS 查询", "dns_response": "DNS 响应",
                        "http_host": "HTTP Host", "tls_sni": "TLS SNI",
                        "dns_candidate": "DNS/IP/TTL 候选",
                    }
                    text += "\n\n域名证据：\n" + "\n".join(
                        f"{item.domain} | {source_labels.get(getattr(item.source, 'value', item.source), str(item.source))}"
                        f" | 原始包 #{item.packet_index + 1}"
                        f" | 关联包 {', '.join('#' + str(index + 1) for index in item.related_packet_indices) or '无'}\n"
                        f"{item.detail}"
                        f"；事务 ID={item.transaction_id if item.transaction_id is not None else '-'}"
                        f"；QNAME={item.qname or '-'}；QTYPE={item.qtype if item.qtype is not None else '-'}"
                        f"；答案={', '.join(item.answers) or '-'}；TTL={item.ttl if item.ttl is not None else '-'}"
                        for item in detail
                    )
                else:
                    text += "\n\n域名证据：未找到可用的包内直接证据。"
            if self.stream_result is not None:
                text = self.stream_result.detail_text(row) + "\n\n" + text
            self.detail_text.setPlainText(text)
        except Exception as exc:
            self.detail_text.setPlainText(f"无法展示该数据包：{exc}")

    def apply_display_filter(self) -> bool:
        """解析并应用显示条件；非法输入保留上一组有效条件。"""
        if self.is_busy() or self._closing:
            return False
        try:
            spec = parse_filter(
                self.protocol_box.currentText(), self.ip_edit.text(), self.port_edit.text(), self.domain_edit.text()
            )
        except ValueError as exc:
            self.filter_status.setText(f"未改变：{exc}（上一组有效条件）")
            return False
        self.filter_spec = spec
        domain_rows = None
        if spec.domain and self.analysis_result is not None:
            domain_rows = self.analysis_result.rows_for_domain(
                spec.domain, include_candidates=self.candidate_box.isChecked()
            )
        self.proxy_model.set_filters(spec, domain_rows)
        details = [spec.protocol]
        if spec.network is not None:
            details.append(str(spec.network))
        if spec.port is not None:
            details.append(f"端口 {spec.port}")
        if spec.domain:
            details.append(f"域名 {spec.domain}")
        self.filter_status.setText(
            "筛选已应用：" + " / ".join(details)
            + f"（{'无匹配' if not self.displayed_packets and self.packets else '显示 ' + str(self.displayed_packets)} / 保留 {len(self.packets)}）"
        )
        self.update_status()
        return True

    def reset_display_filter(self) -> None:
        """清空协议、地址和端口条件并显示全部源数据。"""
        if self.is_busy() or self._closing:
            return
        self.protocol_box.setCurrentText("全部")
        self.ip_edit.clear()
        self.port_edit.clear()
        self.domain_edit.clear()
        self.filter_spec = FilterSpec()
        self.proxy_model.set_filters(self.filter_spec, None)
        self.filter_status.setText("未设置筛选条件")
        self.update_status()

    apply_filter = apply_display_filter

    reset_filter = reset_display_filter
