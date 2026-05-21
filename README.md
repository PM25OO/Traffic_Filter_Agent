# Traffic Filter Agent

基于 LangGraph 的 PCAP 网络流量安全分析工具。输入 PCAP/PCAPNG 文件，通过 5 阶段漏斗流水线自动生成中文 Markdown 安全审计报告。

## 架构概览

```
[Start] → macro_triage → target_extraction → micro_deepdive → threat_intel → report_synthesis → [END]
```

| 阶段 | 用途 | 工具 |
|---|---|---|
| macro_triage | 协议/端点统计，识别 Top-10 可疑 IP | `get_protocol_statistics`, `get_capture_file_info`, `list_tcp_streams` |
| target_extraction | 可疑目标 → Wireshark 显示过滤器 | LLM 推理 |
| micro_deepdive | 逐过滤器深度包分析，检测 VPN/C2/扫描 | `export_packets_json`, `follow_tcp_stream` |
| threat_intel | 公网 IP 威胁情报查询 | AbuseIPDB, URLhaus |
| report_synthesis | 整合生成审计报告 | LLM 推理 |

## 环境配置

### 前置条件

- Python 3.11+
- Wireshark/Tshark（用于深度包解析）
- [Wireshark-MCP](external/Wireshark-MCP/)（项目 external 子目录中附带）

### 1. 克隆并初始化

```bash
git clone <repo-url>
cd Traffic_Filter_Agent

# 创建主项目虚拟环境
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# 初始化 Wireshark-MCP 环境
cd external\Wireshark-MCP
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
cd ..\..
```

### 2. 配置 .env

```bash
cp .env.example .env   # 或直接创建 .env
```

编辑 `.env`，填入必要密钥：

```ini
MODEL_PROVIDER=deepseek              # deepseek 或 openai
MODEL_NAME=deepseek-v4-pro           # 模型名（可选，有默认值）
DEEPSEEK_API_KEY=sk-xxxxxxxx         # DeepSeek API key
DEEPSEEK_BASE_URL=https://api.deepseek.com

# 如果使用 OpenAI
OPENAI_API_KEY=sk-xxxxxxxx
OPENAI_BASE_URL=                     # 可选，自定义 endpoint

# 威胁情报（可选，不填则跳过威胁情报查询）
ABUSEIPDB_API_KEY=                   # https://www.abuseipdb.com/

# LangSmith 追踪（可选）
LANGSMITH_API_KEY=lsv2_xxxxxxxx
```

Wireshark-MCP 路径会自动检测。如路径不标准，可通过以下环境变量覆盖：

```ini
WIRESHARK_MCP_PYTHON=C:\path\to\external\Wireshark-MCP\.venv\Scripts\python.exe
WIRESHARK_MCP_SERVER=C:\path\to\external\Wireshark-MCP\wireshark-mcp-server.py
WIRESHARK_MCP_CWD=C:\path\to\external\Wireshark-MCP
```

## 使用方式

### CLI 模式

```bash
.venv\Scripts\python -m src --pcap <path-to-pcap>
```

完整参数：

```bash
.venv\Scripts\python -m src \
    --pcap testFiles/capture.pcapng \
    --provider deepseek \
    --model deepseek-v4-pro \
    --max-packets 50 \
    --max-iterations 5
```

### Web 交互模式（Streamlit）

```bash
.venv\Scripts\streamlit run app.py
```

1. 左侧上传 PCAP 文件
2. 点击"运行全自动分析流水线"或手动输入分析指令
3. 查看思考过程、工具调用详情和最终回复

### LangGraph Studio

```bash
.venv\Scripts\langgraph dev
```

## 项目结构

```
src/
├── __main__.py        # CLI 入口
├── agent.py           # langgraph dev 兼容层 + ReAct agent
├── graph.py           # StateGraph 构建（5 节点线性 DAG）
├── nodes.py           # 5 个节点实现
├── prompts.py         # 中文 prompt 模板（含检测知识库）
├── state.py           # TrafficAnalysisState TypedDict
├── model_provider.py  # DeepSeek / OpenAI 模型工厂
├── tools.py           # MultiServerMCPClient + 异步工具包装
└── security.py        # 输入校验（BPF 过滤器白名单、IP/端口验证）

app.py                 # Streamlit 聊天界面（文件上传 + 流式输出）
requirements.txt       # 依赖清单
.env                   # 环境变量（不提交到 Git）
```

### 外部依赖

- **Wireshark-MCP**: `external/Wireshark-MCP/` — 通过 `langchain-mcp-adapters` 的 `MultiServerMCPClient` 以 stdio 子进程方式启动
- 模型通过 `langchain-openai` 的 `ChatOpenAI` 兼容 API 接入（DeepSeek 和 OpenAI 均使用该路径）

## 安全设计

- **命令注入防护**: 所有 Wireshark 显示过滤器经过 BPF 字符白名单校验（`validate_display_filter`）
- **ReAct 熔断**: 微观深度分析阶段硬限制最大迭代次数（默认 5）
- **Token 级联控制**: 每过滤器导出数据包硬上限 100 个
- **漏斗减量原则**: 从不直接将全量 PCAP 数据送入 LLM，每阶段指数级减少数据量
