# 新自动化

**完整 Markdown 文件**，可以直接发给 Agent（Codex / 本地 Python Agent）执行，从零生成一套 **开箱可运行的自动化渗透平台**，包含：

- 前期 **Agent Skill 和 MCP 配置**
- Docker 化 Kali 工具链 + PentestGPT / Shannon 集成
- FastAPI + Celery 异步调度
- AI分析模块（漏洞评分、分类、攻击路径规划、报告生成）
- Windows GUI（PyQt5）
- 完整目录结构、示例调用、使用流程

下面是 Markdown 文件示例，可直接发给 Agent 使用：

# AutoSec Platform 完整开箱工程（Agent 指令版）

\# AutoSec Platform 开箱工程 - Agent 指令

\## 1️⃣ 项目目标

开发一个 **开箱可运行的自动化安全测试平台**，特点：

\- Docker 化 Kali 工具链（nuclei, httpx, katana, dirsearch, Metasploit, Impacket, BloodHound 等）

\- FastAPI 后端 + Celery 异步调度

\- AI分析模块：漏洞风险评分、分类、攻击路径规划、报告生成

\- Windows GUI (PyQt5)，可调用 Kali Docker 容器 API 显示结果

\- 自动化攻击插件：PentestGPT / Shannon

\- 支持 Web、CVE、内网、AD、持久化扫描

\- 插件化 + 分布式节点支持

⚠️ 注意：仅用于授权渗透测试或靶场环境。

\---

\## 2️⃣ 前期 Agent Skill / MCP 配置

\### 2.1 必备技能

\- Python 全栈：FastAPI, Celery, PyQt5/PySide6, asyncio

\- Linux/Kali 工具：nuclei, httpx, katana, dirsearch, nmap, Metasploit, Impacket, BloodHound

\- Docker / Docker Compose

\- 异步任务调度与日志管理

\- 数据处理与 AI 分析：JSON/YAML 解析、Graphviz/matplotlib 可视化

\- 安全知识：CVE数据库、CVSS评分、漏洞分类、攻击路径规划

\### 2.2 MCP 依赖安装

\#### Python MCP

\```bash

pip3 install fastapi uvicorn celery redis requests httpx pyqt5 pydantic jinja2 matplotlib graphviz

系统工具（Kali / Linux）

sudo apt update && sudo apt install -y git curl wget python3-pip nmap metasploit-framework \

bloodhound impacket-scripts ruby ruby-dev build-essential golang-go unzip zip graphviz docker.io docker-compose

Kali 工具链安装

TOOLS_DIR="$HOME/tools"

mkdir -p $TOOLS_DIR

git clone <https://github.com/projectdiscovery/subfinder.git> $TOOLS_DIR/subfinder && cd $TOOLS_DIR/subfinder && go build

git clone <https://github.com/projectdiscovery/httpx.git> $TOOLS_DIR/httpx && cd $TOOLS_DIR/httpx && go build

git clone <https://github.com/projectdiscovery/nuclei.git> $TOOLS_DIR/nuclei && cd $TOOLS_DIR/nuclei && go build

git clone <https://github.com/projectdiscovery/katana.git> $TOOLS_DIR/katana && cd $TOOLS_DIR/katana && go build

git clone <https://github.com/maurosoria/dirsearch.git> $TOOLS_DIR/dirsearch

## 3️⃣ 工程目录结构

auto_sec_platform/

├── backend/

│   ├── api/main.py

│   ├── core/orchestrator.py

│   ├── tasks/scan_tasks.py

│   ├── modules/

│   │   ├── recon/recon.py

│   │   ├── webscan/webscan.py

│   │   ├── cve/cve_scan.py

│   │   ├── intranet/intranet_scan.py

│   │   ├── ad/ad_scan.py

│   │   └── persistence/persistence.py

│   ├── ai/

│   │   ├── ai_analysis.py

│   │   ├── model/risk_score.py

│   │   ├── model/vuln_classifier.py

│   │   ├── model/path_planner.py

│   │   └── model/knowledge_base.py

│   └── utils/parser.py

├── frontend/gui/main_gui.py

├── docker/kali/Dockerfile

├── plugins/

│   ├── pentestgpt_plugin.py

│   └── shannon_plugin.py

├── output/

└── docker-compose.yml

## 4️⃣ Docker 配置

### Dockerfile (Kali 工具链)

FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y python3 python3-pip git curl wget nmap metasploit-framework \

bloodhound impacket-scripts ruby ruby-dev build-essential golang-go unzip zip graphviz \

&& apt-get clean

RUN pip3 install --no-cache-dir fastapi uvicorn celery redis requests httpx pyqt5 pydantic jinja2 matplotlib graphviz

WORKDIR /workspace

VOLUME ["/workspace/output"]

### docker-compose.yml

version: "3.9"

services:

  backend:

​    build: ./backend

​    container_name: auto_sec_backend

​    volumes:

​      \- ./output:/workspace/output

​    ports:

​      \- "8000:8000"

​    depends_on:

​      \- redis

​    command: uvicorn api.main:app --host 0.0.0.0 --port 8000

  worker:

​    build: ./backend

​    container_name: auto_sec_worker

​    volumes:

​      \- ./output:/workspace/output

​    depends_on:

​      \- redis

​    command: celery -A tasks.scan_tasks worker --loglevel=info

  redis:

​    image: redis:alpine

​    container_name: auto_sec_redis

​    ports:

​      \- "6379:6379"

  kali:

​    build: ./docker/kali

​    container_name: auto_sec_kali

​    volumes:

​      \- ./output:/workspace/output

​    tty: true

  pentestgpt:

​    image: pentestgpt/pentestgpt:latest

​    container_name: pentestgpt

​    volumes:

​      \- ./output:/workspace/output

​    depends_on:

​      \- backend

  shannon:

​    image: shannon:latest

​    container_name: shannon

​    volumes:

​      \- ./output:/workspace/output

​    depends_on:

​      \- backend

## 5️⃣ FastAPI 后端

- 提供 /scan/web、/ai/analyze、/results
- Celery 异步任务执行扫描和 AI 分析
- 插件调用 PentestGPT / Shannon

## 6️⃣ AI分析模块

- **risk_score.py**：漏洞风险评分
- **vuln_classifier.py**：漏洞分类
- **path_planner.py**：攻击路径规划
- **ai_analysis.py**：Celery 异步分析 + JSON/HTML 输出

> 可调用外部 AI 或本地 LLM（GPT4All/MPT）

## 7️⃣ Windows GUI (PyQt5)

- 漏洞表格、攻击路径图、日志窗口
- 支持报告导出（JSON/HTML）
- 调用 Kali Docker 后端 + PentestGPT / Shannon 插件 API

## 8️⃣ 使用流程

1. 构建 Docker：

docker-compose build

1. 启动服务：

docker-compose up

1. 运行 Windows GUI：

python frontend/gui/main_gui.py

1. 输入目标扫描结果或 ID → 点击 **运行 AI 分析**
2. GUI 显示漏洞表 + 攻击路径 + 日志，报告可导出

## 9️⃣ 扩展能力

- 多目标分布式扫描（多个 worker 容器）
- 插件化 AI分析模块（外部 AI / 本地 LLM）
- 攻击路径可视化（Graphviz / matplotlib）
- Celery 异步分布式处理，保证 GUI不卡死
- 历史扫描数据学习优化风险排序

## 10️⃣ 总结

- Docker 化 Kali + 工具链
- FastAPI + Celery 异步调度
- AI 分析模块：漏洞评分、分类、攻击路径、报告生成
- Windows GUI：统一控制与可视化
- 集成 PentestGPT / Shannon 自动化攻击
- 插件化 + 分布式 + 可扩展

> 可直接交给 Agent 执行，从零生成 **完整开箱可运行工程**。



# win系统

# 🟢 Windows GUI 快速启动指南

## 1️⃣ 前提条件

1. **Windows 已安装 Python 3.10+**

- 官网下载安装：<https://www.python.org/downloads/>

1. **安装必要依赖**

打开 CMD / PowerShell 执行：

pip install pyqt5 requests matplotlib graphviz

> matplotlib 和 graphviz 用于攻击路径可视化，如果你不需要路径图，可以先不安装。

1. **确保 Kali Docker 已部署并启动**

- 端口映射示例：

ports:

  \- "8000:8000"

- 确认 Kali 主机 IP（虚拟机或物理机），Windows 可访问该 IP。

## 2️⃣ GUI 脚本模板

创建文件：run_autosec_gui.py

import sys, requests, json

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem

\# 修改这里为你的 Kali Docker 宿主机 IP

API_URL = "http://<KALI_HOST_IP>:8000"

class AutoSecGUI(QWidget):

​    def __init__(self):

​        super().__init__()

​        self.setWindowTitle("AutoSec Platform GUI")

​        self.setGeometry(100, 100, 1000, 600)

​        layout = QVBoxLayout()

​        \# 输入目标

​        self.target_input = QLineEdit()

​        self.target_input.setPlaceholderText("输入目标 URL 或 IP")

​        layout.addWidget(self.target_input)

​        \# 操作按钮

​        self.scan_btn = QPushButton("开始扫描")

​        self.scan_btn.clicked.connect(self.start_scan)

​        layout.addWidget(self.scan_btn)

​        self.ai_btn = QPushButton("运行 AI 分析")

​        self.ai_btn.clicked.connect(self.run_ai)

​        layout.addWidget(self.ai_btn)

​        \# 漏洞表格

​        self.vuln_table = QTableWidget()

​        self.vuln_table.setColumnCount(4)

​        self.vuln_table.setHorizontalHeaderLabels(["漏洞ID", "类型", "分类", "风险等级"])

​        layout.addWidget(self.vuln_table)

​        \# 攻击路径和日志

​        self.log_window = QTextEdit()

​        self.log_window.setReadOnly(True)

​        layout.addWidget(self.log_window)

​        self.setLayout(layout)

​        self.analysis_results = {}

​    def start_scan(self):

​        target = self.target_input.text()

​        if not target:

​            self.log_window.append("请输入目标！")

​            return

​        try:

​            self.log_window.append(f"启动扫描任务: {target}")

​            resp = requests.post(f"{API_URL}/scan/web", json={"target": target})

​            self.log_window.append(str(resp.json()))

​        except Exception as e:

​            self.log_window.append(f"扫描失败: {str(e)}")

​    def run_ai(self):

​        \# 假设扫描结果文件名固定为 output/scan_result.json

​        file_path = "output/scan_result.json"

​        try:

​            self.log_window.append("启动 AI 分析...")

​            resp = requests.post(f"{API_URL}/ai/analyze", json={"file_path": file_path})

​            self.analysis_results = resp.json()

​            self.populate_table()

​            self.log_window.append("AI 分析完成")

​        except Exception as e:

​            self.log_window.append(f"AI 分析失败: {str(e)}")

​    def populate_table(self):

​        vulns = self.analysis_results.get("vulnerabilities", [])

​        self.vuln_table.setRowCount(len(vulns))

​        for i, v in enumerate(vulns):

​            self.vuln_table.setItem(i, 0, QTableWidgetItem(v.get("vuln_id", "")))

​            self.vuln_table.setItem(i, 1, QTableWidgetItem(v.get("type", "")))

​            self.vuln_table.setItem(i, 2, QTableWidgetItem(v.get("category", "")))

​            self.vuln_table.setItem(i, 3, QTableWidgetItem(str(v.get("priority", ""))))

if __name__ == "__main__":

​    app = QApplication(sys.argv)

​    gui = AutoSecGUI()

​    gui.show()

​    sys.exit(app.exec_())

## 3️⃣ 启动方法

1. 打开 Windows 命令行，进入 GUI 脚本目录
2. 确保 Kali Docker 已启动且可访问端口 8000
3. 运行：

python run_autosec_gui.py

1. GUI 界面会弹出：

- 输入目标 URL / IP
- 点击“开始扫描” → 调用 Kali Docker 扫描
- 点击“运行 AI 分析” → 处理漏洞、攻击路径
- 漏洞表格、日志窗口显示结果

## 4️⃣ 网络要求

- Windows 可以访问 Kali 宿主机 IP + API 端口
- 虚拟机模式：


- NAT 模式 → 需要端口映射
- 桥接模式 → Windows 与 Kali 在同一局域网，可直接访问 IP

✅ **总结**

- **Kali 端**：运行 Docker 容器，包含扫描工具、AI 分析、插件
- **Windows 端**：只运行 GUI 脚本，通过 API 调用 Kali 容器
- GUI 功能完整，**无需在 Windows 再安装渗透工具或 AI 模块**
- 美观和高保真效果可以通过 PyQt5 样式表进一步调整