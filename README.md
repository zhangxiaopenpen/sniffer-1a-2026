# 网络嗅探器课程项目

这是一个面向 Windows 的网络嗅探器课程项目，计划使用 Python、Scapy 和 PySide6，按阶段逐步实现并验收。

仓库地址：<https://github.com/zhangxiaopenpen/sniffer-1a-2026>

## 当前进度

当前为阶段 0，仅完成项目初始化文件。尚未创建应用源码或程序入口，也尚未实现抓包、界面或分析功能。下面的命令用于准备开发环境和检查依赖导入，不会启动抓包程序。

每个阶段完成并推送后，由用户验收，通过后再继续下一阶段。提交记录以 Git 历史为准。

## 环境要求

- Windows。
- Git，用于下载项目及管理版本。
- Python 3.14.3，安装时保留 Python Launcher（`py` 命令）。
- Npcap，供 Scapy 在 Windows 上访问抓包驱动。
- 项目直接依赖固定为 Scapy 2.8.0、PySide6 6.12.0，见 `requirements.txt`。

Npcap 是 Windows 驱动，需要单独安装，不能通过 `pip` 安装。官方下载地址：<https://npcap.com/#download>。当前开发机器已安装 Npcap，无需重复安装；在其他机器上准备环境时，请先检查是否已安装。

## 在 PowerShell 中准备环境

打开 PowerShell，先进入希望存放项目的文件夹，然后执行：

```powershell
git clone https://github.com/zhangxiaopenpen/sniffer-1a-2026.git
cd sniffer-1a-2026
```

检查 Python 版本，预期为 `Python 3.14.3`：

```powershell
py -3.14 -X utf8 --version
```

在项目目录内创建独立虚拟环境：

```powershell
py -3.14 -X utf8 -m venv .venv
```

直接调用虚拟环境中的 Python 安装依赖，无须激活虚拟环境：

```powershell
.\.venv\Scripts\python.exe -X utf8 -m pip install -r requirements.txt
```

验证 PySide6 和 Scapy 能否导入，并检查依赖冲突：

```powershell
.\.venv\Scripts\python.exe -X utf8 -c "import PySide6; import scapy; print('PySide6:', PySide6.__version__); print('Scapy:', scapy.__version__)"
.\.venv\Scripts\python.exe -X utf8 -m pip check
```

版本输出应分别为 `6.12.0` 和 `2.8.0`；依赖检查正常时会输出 `No broken requirements found.`。这些检查只验证 Python 依赖，不代表已经验证真实抓包。

## 阶段路线

| 阶段 | 计划内容 | 当前状态 |
| --- | --- | --- |
| 0 | 初始化独立项目、依赖清单、Git 配置与开发文档 | 初始化文件已完成；推送后由用户验收 |
| 1 | 实现命令行真实抓包 | 待实施 |
| 2 | 实现莫兰迪浅色 GUI、稳定性处理与保存功能 | 待实施 |
| 3 | 实现过滤与抓包文件导入 | 待实施 |
| 4 | 实现域名相关功能 | 待实施 |
| 5 | 实现 TCP 流相关功能 | 待实施 |
| 6 | 完成报告、演示与最终回归 | 待实施 |

## 文件与数据管理

- `requirements.txt`：两个直接依赖的固定版本。
- `.gitignore`：排除虚拟环境、缓存、构建产物、本地配置、日志和敏感文件。
- `.gitattributes`：统一文本换行，并声明常见二进制文件类型。
- `docs/开发记录.md`：记录本阶段实际检查与初始化内容。

所有 `.pcap`、`.pcapng` 文件默认忽略，避免提交真实抓包数据。后续如需提供示例，仅在审核合成样本后，按具体文件路径显式允许提交。
