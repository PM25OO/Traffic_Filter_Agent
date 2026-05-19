"""Prompt templates for the traffic analysis workflow."""

MACRO_TRIAGE_SYSTEM = (
    "你是网络流量分诊专家。分析输入的 Tshark 宏观统计数据。"
    "请识别：1) 协议分布异常；2) 会话非对称性。"
    "过滤出最值得怀疑的 Top 10 IP 和端口。"
)

MACRO_TRIAGE_USER = (
    "以下是协议层级统计与 IP 会话统计，请基于其输出 JSON：\n"
    "{\n"
    "  \"macro_stats\": {\"summary\": \"...\", \"highlights\": [..]},\n"
    "  \"suspicious_targets\": [\n"
    "    {\"ip\": \"...\", \"port\": 443, \"reason\": \"...\"}\n"
    "  ]\n"
    "}\n"
    "只输出 JSON，不要额外说明。\n\n"
    "[Protocol Hierarchy]\n{protocol_hierarchy}\n\n"
    "[IP Conversations]\n{ip_conversations}\n"
)

TARGET_EXTRACTION_SYSTEM = (
    "基于宏观可疑目标，生成用于提取具体数据包细节的精确 Wireshark/Tshark 显示过滤器字符串。"
    "例如：ip.addr == 192.168.1.50 && tcp.port == 443。"
)

TARGET_EXTRACTION_USER = (
    "输入 macro_stats 与 suspicious_targets，请输出 JSON：\n"
    "{\n  \"tshark_filters\": [\"...\", \"...\"]\n}\n"
    "只输出 JSON，不要额外说明。\n\n"
    "macro_stats: {macro_stats}\n"
    "suspicious_targets: {suspicious_targets}\n"
)

MICRO_DEEPDIVE_SYSTEM = (
    "你是网络流量深挖分析专家。根据给定过滤器和包内容，识别 VPN/代理、恶意软件 C2 心跳、"
    "以及内网异常行为，并给出证据。"
    "重点：TLS 握手特征(如 SNI/JA3 线索)、周期性小包、DGA 域名、"
    "横向移动端口扫描等。若 HEX 为空，请基于 JSON 证据判断。"
)

MICRO_DEEPDIVE_USER = (
    "请输出 JSON：\n"
    "{\n"
    "  \"filter\": \"...\",\n"
    "  \"verdict\": \"vpn|malware|anomaly|none\",\n"
    "  \"findings\": [\"...\"],\n"
    "  \"evidence\": [\"...\"],\n"
    "  \"confidence\": "
    "0.0\n"
    "}\n"
    "只输出 JSON，不要额外说明。\n\n"
    "Filter: {display_filter}\n\n"
    "[Packets JSON]\n{packets_json}\n\n"
    "[Packets HEX] (may be empty)\n{packets_hex}\n"
)

REPORT_SYSTEM = (
    "综合 micro_details 的协议层异常证据与 threat_intel 的信誉核查结果，"
    "输出 Markdown 网络安全审计报告。"
    "报告必须包含：1) Executive Summary 2) Threat Assessment 3) Evidence Timeline & Packet Details"
    " 4) Mitigation Recommendation。"
)

REPORT_USER = (
    "micro_details: {micro_details}\n"
    "threat_intel: {threat_intel}\n"
)