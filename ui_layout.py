"""第二阶段嗅探器布局和莫兰迪浅色样式。"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QPushButton, QSpinBox,
    QSplitter, QTableView, QTextEdit, QVBoxLayout, QWidget,
)

from packet_model import PacketTableModel


def build_layout(window) -> None:
    """构建控制区、八列表格和下方详情，并连接生命周期方法。

    Args:
        window: 提供抓包、停止、清空、保存和状态方法的主窗口。
    """
    root = QWidget()
    window.setCentralWidget(root)
    layout = QVBoxLayout(root)
    layout.setContentsMargins(20, 18, 20, 18)
    layout.setSpacing(10)
    title = QLabel("网络嗅探器")
    title.setObjectName("title")
    subtitle = QLabel("实验 1A · 第二阶段 · 实时抓包与数据包查看")
    subtitle.setObjectName("subtitle")
    layout.addWidget(title)
    layout.addWidget(subtitle)

    controls = QHBoxLayout()
    controls.setSpacing(9)
    controls.addWidget(QLabel("网卡"))
    window.interface_box = QComboBox()
    window.interface_box.setMinimumWidth(250)
    window.interface_box.setToolTip("默认建议为 Scapy 当前默认接口；已有数据时请先停止并清空再更换网卡")
    controls.addWidget(window.interface_box, 1)
    for name, text, callback in (
        ("start_button", "开始抓包", window.start_capture),
        ("stop_button", "停止", window.stop_capture),
        ("clear_button", "清空", window.clear_packets),
        ("save_button", "保存 pcap", window.save_capture),
    ):
        button = QPushButton(text)
        button.setObjectName(name)
        setattr(window, name, button)
        button.clicked.connect(callback)
        controls.addWidget(button)
    layout.addLayout(controls)

    limits = QHBoxLayout()
    limits.addWidget(QLabel("最多保留"))
    window.limit_box = QSpinBox()
    window.limit_box.setRange(10, 10000)
    window.limit_box.setValue(1000)
    window.limit_box.setSuffix(" 包")
    window.limit_box.setToolTip("范围 10–10000 包；停止并清空后可修改")
    window.limit_box.valueChanged.connect(window.change_limit)
    limits.addWidget(window.limit_box)
    limits.addWidget(QLabel("或 32 MiB 原始数据，达到任一上限自动停止"))
    limits.addStretch()
    layout.addLayout(limits)

    window.status_label = QLabel()
    window.status_label.setObjectName("status")
    window.status_label.setWordWrap(True)
    window.counter_label = QLabel()
    window.counter_label.setObjectName("counters")
    window.counter_label.setWordWrap(True)
    window.counter_label.setToolTip(
        "仅统计进入应用回调的包，不含网卡或 Npcap 驱动丢包。\n"
        "保留数包含已显示与待处理；原始字节预算不等于进程内存上限。"
    )
    layout.addWidget(window.status_label)
    layout.addWidget(window.counter_label)

    window.packet_model = PacketTableModel(window)
    window.packet_table = QTableView()
    window.packet_table.setModel(window.packet_model)
    window.packet_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
    window.packet_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
    window.packet_table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
    window.packet_table.setAlternatingRowColors(True)
    window.packet_table.setWordWrap(False)
    window.packet_table.setSortingEnabled(False)
    window.packet_table.verticalHeader().hide()
    window.packet_table.verticalHeader().setDefaultSectionSize(30)
    header = window.packet_table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    for column, width in enumerate((62, 112, 235, 235, 90, 90, 90, 70)):
        window.packet_table.setColumnWidth(column, width)
    header.setStretchLastSection(True)

    details = QWidget()
    detail_layout = QVBoxLayout(details)
    detail_layout.setContentsMargins(0, 5, 0, 0)
    detail_layout.setSpacing(6)
    detail_layout.addWidget(QLabel("数据包详情"))
    window.detail_text = QTextEdit()
    window.detail_text.setReadOnly(True)
    window.detail_text.setFont(QFont("Consolas", 10))
    window.detail_text.setPlaceholderText("选择表格中的一行，查看协议字段与十六进制原始数据")
    detail_layout.addWidget(window.detail_text)
    splitter = QSplitter(Qt.Orientation.Vertical)
    splitter.setChildrenCollapsible(False)
    splitter.addWidget(window.packet_table)
    splitter.addWidget(details)
    splitter.setSizes([360, 180])
    layout.addWidget(splitter, 1)
    window.packet_table.selectionModel().selectionChanged.connect(window.show_selected_packet)


def apply_style(app) -> None:
    """应用莫兰迪浅色配色，并保留清晰的正文及选中状态对比。

    Args:
        app: 应用样式的 QApplication 实例。
    """
    app.setFont(QFont("Microsoft YaHei", 10))
    app.setStyleSheet("""
        QWidget { background: #F4F1EE; color: #484642; }
        QLabel#title { color: #607770; font-size: 26px; font-weight: 700; }
        QLabel#subtitle { color: #706A65; }
        QLabel#status { background: #E4E9E4; color: #3D594F;
            border-radius: 7px; padding: 9px; }
        QLabel#counters { color: #5A625E; padding: 3px; }
        QComboBox, QSpinBox, QTextEdit, QTableView {
            background: #FCFAF8; border: 1px solid #D7D0CA; border-radius: 6px; }
        QComboBox, QSpinBox { padding: 7px; }
        QComboBox:disabled, QSpinBox:disabled { background: #ECEAE6; color: #817F79; }
        QPushButton { background: #C9D5CF; color: #324D41; border: none;
            border-radius: 6px; padding: 9px 15px; }
        QPushButton#start_button { background: #A8BBB1; }
        QPushButton#stop_button { background: #D8C7BC; color: #60483E; }
        QPushButton:hover { background: #ADC1B6; }
        QPushButton:disabled, QPushButton#start_button:disabled,
        QPushButton#stop_button:disabled { background: #DFE1DD; color: #838980; }
        QHeaderView::section { background: #D7E0DA; color: #45564D;
            padding: 8px; border: none; }
        QTableView { alternate-background-color: #F5F2EF; gridline-color: #E4DED8; }
        QTableView::item:selected { background: #CCDCD2; color: #324D41; }
        QSplitter::handle { background: #D8D0CA; height: 4px; }
    """)
