# 流量分析智能体
## 任务描述
创建一个静态流量分析智能体，负责分析网络流量数据并提供有用的见解和建议。根据提供的.pcapng或.pcap文件提取有价值的信息，识别潜在的安全威胁。重点是识别**VPN流量、恶意软件通信和异常行为**。
## 具体功能
- [ ] 解析.pcapng或.pcap文件
- [ ] 提取网络流量数据
- [ ] 识别VPN流量
- [ ] 识别恶意软件通信
- [ ] 识别异常行为
- [ ] 提供安全威胁报告
- [ ] 提供网络性能优化建议
## 工具
### MCP服务
使用[mixelpixx/Wireshark-MCP](https://github.com/mixelpixx/Wireshark-MCP)作为MCP服务（单独创建python虚拟环境），解析.pcapng或.pcap文件并提取网络流量数据.
### 其他工具
- [Scapy](https://scapy.net/): 用于网络数据包处理和分析的Python库。
- [PyShark](https://github.com/KimiNewt/pyshark): 用于解析和分析网络数据包的Python库.
- （待补充）

## 1. 核心设计哲学 (Core Philosophy)

* **漏斗式分治 (Macro-to-Micro Triage):** 禁止让 AI 直接读取全量原始 PCAP 数据包。必须通过多阶段节点逐步过滤，实现数据量指数级下降。
* **确定性拓扑 vs 局部灵活性:** 使用 LangGraph 编排宏观的确定性工作流，仅在微观“深挖与解码”节点允许 ReAct 智能体进行多轮工具调度。
* **外部上下文增强 (Context Enrichment):** 结合 Tshark 解析、MCP 威胁情报插件以及主动网络扫描（Nmap），构建三位一体的研判能力。

---

## 2. 系统拓扑图 (System Topology)

```
[Start] --> Node: Macro_Triage (Protocol/Endpoint Stats)
                 |
                 v
            Node: Target_Extraction (Generate Tshark Filters)
                 |
                 v
            Node: Micro_DeepDive (Micro ReAct Agent: Fetch JSON/Payloads)
                 |
                 v
            Node: Threat_Intel (Query AbuseIPDB / URLhaus)
                 |
                 v
            Node: Report_Synthesis (Final Security Audit Report) --> [End]

```

---

## 3. LangGraph 状态与节点实现规范 (Implementation Specification)

### 3.1 全局状态定义 (State Definition)

AI 编码助手在生成状态时，必须严格遵循以下 `TypedDict` 结构，以确保节点间上下文的强类型传递：

```python
from typing import TypedDict, List, Dict, Any

class TrafficAnalysisState(TypedDict):
    pcap_path: str                 # 输入：PCAP 文件的绝对路径
    macro_stats: Dict[str, Any]    # 宏观流量特征统计（分层协议、Top 终点）
    suspicious_targets: List[Dict] # 筛选出的可疑指标列表：[{'ip': ..., 'port': ..., 'reason': ...}]
    tshark_filters: List[str]      # 动态生成的 Tshark 显示过滤器表达式
    micro_details: List[Dict]      # 针对特定流的深度解析与十六进制 Payload 结果
    threat_intel: List[Dict]       # 外部威胁情报联动命中结果
    final_report: str              # 最终生成的 Markdown 格式审计报告

```

### 3.2 节点流水线与 Prompt 指南 (Nodes & Prompt Engineering)

#### 🛠️ 节点 1: `macro_triage_node`

* **目标:** 快速获取 PCAP 的全局画像，识别宏观异常。
* **工具调用:** `mixelpixx/Wireshark-MCP` 的 `tshark` 统计工具（如：协议分层统计、IP 终点会话列表）。
* **AI 助手编写提示 (System Prompt):**
> 你是网络流量分诊专家。分析输入的 Tshark 宏观统计数据。请识别：
> 1. 协议分布异常（如：内网向外发送大量非常规端口的 UDP/TLS 流量）。
> 2. 会话非对称性（如：单一外部 IP 与内网频繁交互但每次报文极小）。
> 过滤出最值得怀疑的 Top 10 IP 和端口，写入状态的 `macro_stats` 中。
> 
> 



#### 🛠️ 节点 2: `target_extraction_node`

* **目标:** 将模糊的“可疑点”转化为确定性的 Tshark 过滤表达式。
* **逻辑:** 纯逻辑/LLM 节点，不调用外部工具。
* **AI 助手编写提示 (System Prompt):**
> 基于 `macro_stats` 中的可疑目标，生成用于提取具体数据包细节的精确 Wireshark/Tshark 显示过滤器字符串（Display Filters）。
> 例如：生成 `"ip.addr == 192.168.1.50 && tcp.port == 443"` 或 `"dns.flags.response == 0"`。将过滤器数组保存到 `tshark_filters`。



#### 🛠️ 节点 3: `micro_deepdive_node` (Micro ReAct Agent)

* **目标:** 针对过滤出的会话进行微观深挖，识别特定威胁场景。
* **行为模式:** 启动一个局部的 ReAct 循环。允许 LLM 反复调用 `tshark` 抓取特定帧的 JSON/Payload。
* **三大场景专项识别指南 (必须注入到 Prompt 中):**
* **VPN/代理流量识别:** 检查 TLS 握手特征（JA3 指纹）、不透明的 UDP 持续高带宽传输、高熵的 SNI 扩展或空白 SNI 现象。
* **恶意软件 C2 心跳 (Beaconing):** 检查指定 IP 交互的时间戳。计算连接间隔的方差，识别是否存在严格周期性（例如：固定每 60 秒一次的 0 字节或极小字节交互）。检查 DNS 是否包含大批量 DGA 随机域名。
* **内网异常行为:** 分析是否存在横向移动特征（单一源 IP 短时间内向内网不同主机发起大量 SYN 握手或 445/3389 端口探测）。可在此处调用 **Nmap 插件** 进行服务存活验证。



#### 🛠️ 节点 4: `threat_intel_node`

* **目标:** 利用外部威胁情报为可疑 IP/域名“定性”。
* **工具调用:** 调用 `Wireshark-MCP` 内置的 `AbuseIPDB` 或 `URLhaus` 接口。
* **逻辑:** 遍历 `suspicious_targets` 中的外部 IP，全自动进行信誉核查，将恶意得分与标签合并进 `threat_intel` 状态。

#### 🛠️ 节点 5: `report_synthesis_node`

* **目标:** 生成面向安全运维人员的最终报告。
* **AI 助手编写提示 (System Prompt):**
> 综合 `micro_details` 的协议层异常证据与 `threat_intel` 的信誉核查结果。
> 请输出一份标准的 **Markdown 网络安全审计报告**。报告必须严格包含以下小节：
> 1. **Executive Summary (概要)**
> 2. **Threat Assessment (VPN/恶意软件/异常行为的检出结论)**
> 3. **Evidence Timeline & Packet Details (具体的 IP、时间戳、JA3 或 DGA 证据链)**
> 4. **Mitigation Recommendation (处置建议)**
> 
> 



---

## 4. 给 Copilot 的代码生成防御性警示 (Defensive Coding Guarantees)

为了防止 Copilot 在自动生成 Python 代码时引入死循环或安全漏洞，请确保代码包含以下约束：

1. **严格的命令注入防御:** 当调用 `tshark` 或 `nmap` 相关的 MCP 工具时，所有的过滤器字符串（`tshark_filters`）和 IP 参数必须经过严格的白名单校验（仅允许标准的 BPF 语法字符、IPv4/IPv6 地址、数字端口），防止通过恶意包构造触发二次命令注入。
2. **ReAct 步数熔断机制 (Max Iterations):** 在 `micro_deepdive_node` 的 ReAct 循环中，必须硬编码限制 AI 调用的最大步数（例如 `max_iterations = 5`），防止因复杂 Payload 无法解码导致 Agent 陷入死循环、刷爆 Token 额度。
3. **Token 级联控制:** 如果某一条 Tshark 过滤器返回的数据包行数超过 100 行，必须在代码层强制截断（使用 `tshark -c 100`），绝不允许将成千上万行的原始 JSON 报文丢入 LLM 上下文。
