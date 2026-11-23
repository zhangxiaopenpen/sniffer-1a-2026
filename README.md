# 网络嗅探器课程项目

这是一个面向 Windows 的网络嗅探器课程项目，计划使用 Python、Scapy 和 PySide6，按阶段逐步实现并验收。

仓库地址：<https://github.com/zhangxiaopenpen/sniffer-1a-2026>

## 当前进度

阶段 0 已通过用户审核。阶段 1 已实现命令行真实抓包并完成开发验证，等待用户验收；阶段 2 至阶段 6 尚未开始。

每个阶段完成并推送后，由用户验收，通过后再继续下一阶段。提交记录以 Git 历史为准。

## 本机快速开始

本项目的独立 `.venv` 已创建并安装依赖，本机 Npcap 服务正常，无需重复安装。打开 PowerShell，进入项目目录后直接运行虚拟环境的 Python，无需激活环境：

```powershell
.\.venv\Scripts\python.exe -X utf8 .\sniffer_cli.py --help
.\.venv\Scripts\python.exe -X utf8 .\sniffer_cli.py --list
.\.venv\Scripts\python.exe -X utf8 .\sniffer_cli.py
```

无参数运行时会列出网卡并提示选择：输入本次列表序号或精确名称，回车选择有“默认建议”标记的网卡，输入 `q` 取消。默认最多捕获 20 个包、等待 30 秒，以先达到者为准；也可按 `Ctrl+C` 停止。

测试本机回环通信时，可直接使用 `loopback`，无需猜测网卡名称：

```powershell
.\.venv\Scripts\python.exe -X utf8 .\sniffer_cli.py --iface loopback --count 0 --timeout 20
```

看到“抓包已就绪”后，在**第二个 PowerShell 窗口**执行 `ping 127.0.0.1`，让流量产生在抓包期间。回环接口也可能包含其他本机流量，输出较多属于正常情况；本阶段不支持协议筛选。逐项操作见 [阶段 1 验收流程](docs/阶段1验收流程.md)。

## 阶段 1 命令说明

| 参数 | 行为 |
| --- | --- |
| `--list` | 列出序号、名称、描述、IPv4、默认建议/回环标记和设备标识后退出 |
| `--iface` / `-i` | 选择本次列表序号、精确名称/描述/设备标识，或回环别名 `loopback` |
| `--count` / `-c` | 非负整数，默认 `20`；`0` 表示不限数量 |
| `--timeout` / `-t` | 非负有限秒数，可为小数，默认 `30`；`0` 表示不限时间 |

数量与超时同时生效，以先达到者为准；两者均为 `0` 时持续抓包，使用 `Ctrl+C` 停止。非交互环境必须提供 `--iface`。列表序号只对应本次枚举，脚本调用优先使用 `loopback` 或精确设备标识。

每个包显示序号、时间、字节长度及 Scapy 摘要，结束时显示本程序收到的包数。程序使用 `store=False`、`promisc=False`，不保留包列表，不保存抓包文件；本阶段没有 GUI、协议筛选或协议分析界面。

## 其他机器首次准备环境

需要 Windows、Git、Python 3.14.3（包含 `py` 命令）和 Npcap。直接依赖固定为 Scapy 2.8.0、PySide6 6.12.0，见 `requirements.txt`；PySide6 为后续 GUI 阶段准备。

Npcap 是需单独安装的 Windows 驱动，不能通过 `pip` 安装。先检查是否已安装；未安装时从 <https://npcap.com/#download> 获取，并启用 WinPcap API 兼容选项。若驱动限制为管理员访问，请以管理员身份打开 PowerShell。

在希望存放项目的文件夹打开 PowerShell，下载项目；已有项目时直接进入实际项目路径：

```powershell
git clone https://github.com/zhangxiaopenpen/sniffer-1a-2026.git
cd sniffer-1a-2026
```

仅在尚未准备环境时，在项目目录内检查 Python 版本、创建独立虚拟环境并安装依赖：

```powershell
py -3.14 -X utf8 --version
py -3.14 -X utf8 -m venv .venv
.\.venv\Scripts\python.exe -X utf8 -m pip install -r requirements.txt
```

验证 PySide6 和 Scapy 能否导入，并检查依赖冲突：

```powershell
.\.venv\Scripts\python.exe -X utf8 -c "import PySide6; import scapy; print('PySide6:', PySide6.__version__); print('Scapy:', scapy.__version__)"
.\.venv\Scripts\python.exe -X utf8 -m pip check
```

版本输出应分别为 `6.12.0` 和 `2.8.0`；依赖检查正常时会输出 `No broken requirements found.`。这些检查只验证 Python 依赖，不代表已经验证真实抓包。

## 已完成的开发验证

- 新项目独立环境：Python 3.14.3、Scapy 2.8.0、PySide6 6.12.0；Npcap 为 Running，`conf.use_pcap=True`，`pip check` 无冲突。
- 离线单元测试：`unittest discover -s tests -v`，22 项全部通过；使用模拟对象验证参数、选卡及抓包调用等逻辑。
- 真实 Npcap 捕获：回环 UDP 和 `ping 127.0.0.1` 的 ICMP 请求/应答均已验证；超时停止、真实 Windows `Ctrl+C` 正常退出也已验证。

运行离线测试：

```powershell
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -v
```

真实抓包结果与离线测试分别记录在 [开发记录](docs/开发记录.md)，仍需用户完成阶段 1 验收。

## 阶段路线

| 阶段 | 计划内容 | 当前状态 |
| --- | --- | --- |
| 0 | 初始化独立项目、依赖清单、Git 配置与开发文档 | 用户审核已通过 |
| 1 | 实现命令行真实抓包 | 实现与开发验证完成，等待用户验收 |
| 2 | 实现莫兰迪浅色 GUI、稳定性处理与保存功能 | 未开始 |
| 3 | 实现过滤与抓包文件导入 | 未开始 |
| 4 | 实现域名相关功能 | 未开始 |
| 5 | 实现 TCP 流相关功能 | 未开始 |
| 6 | 完成报告、演示与最终回归 | 未开始 |

## 文件与数据管理

- `requirements.txt`：两个直接依赖的固定版本。
- `.gitignore`：排除虚拟环境、缓存、构建产物、本地配置、日志和敏感文件。
- `.gitattributes`：统一文本换行，并声明常见二进制文件类型。
- `sniffer_cli.py`：阶段 1 命令行入口。
- `tests/`：离线单元测试。
- `docs/开发记录.md`：记录各阶段实现和验证结果。
- `docs/阶段1验收流程.md`：面向用户的实际操作步骤。

所有 `.pcap`、`.pcapng` 文件默认忽略，避免提交真实抓包数据。抓包日志与临时验证脚本仅保留在本地，不提交。后续如需提供示例，仅在审核合成样本后，按具体文件路径显式允许提交。
