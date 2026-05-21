"""LangGraph nodes for traffic analysis."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Dict, List

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from mcp import ClientSession

from .prompts import (
    MACRO_TRIAGE_SYSTEM,
    MACRO_TRIAGE_USER,
    MICRO_DEEPDIVE_SYSTEM,
    MICRO_DEEPDIVE_USER,
    REPORT_SYSTEM,
    REPORT_USER,
    TARGET_EXTRACTION_SYSTEM,
    TARGET_EXTRACTION_USER,
)
from .security import (
    ensure_pcap_path,
    limit_list,
    validate_display_filter,
    validate_ip,
    validate_port,
)
from .state import TrafficAnalysisState
from .tools import create_macro_triage_tools, create_micro_deepdive_tools


@dataclass(frozen=True)
class NodeConfig:
    model: BaseChatModel
    session: ClientSession
    max_packets: int = 100
    max_iterations: int = 5


def _safe_json_loads(payload: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return fallback


def _normalize_suspicious_targets(raw_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for target in raw_targets:
        try:
            ip_value = validate_ip(str(target.get("ip", "")))
        except ValueError:
            continue
        port_value = target.get("port")
        try:
            port_value = validate_port(port_value)
        except ValueError:
            port_value = None
        reason = str(target.get("reason", "unknown"))
        entry: Dict[str, Any] = {"ip": ip_value, "reason": reason}
        if port_value is not None:
            entry["port"] = port_value
        normalized.append(entry)
    return normalized


def _fallback_filters(suspicious_targets: List[Dict[str, Any]]) -> List[str]:
    filters: List[str] = []
    for target in suspicious_targets:
        ip_value = target.get("ip")
        port_value = target.get("port")
        if port_value is None:
            filters.append(f"ip.addr == {ip_value}")
        else:
            filters.append(
                "ip.addr == {ip} && (tcp.port == {port} || udp.port == {port})".format(
                    ip=ip_value, port=port_value
                )
            )
    return filters


# ---------------------------------------------------------------------------
# Node 1 — Macro Triage
# ---------------------------------------------------------------------------


def macro_triage_node(config: NodeConfig):
    async def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        pcap_path = ensure_pcap_path(state["pcap_path"])
        tools = create_macro_triage_tools(config.session, pcap_path)
        agent = create_agent(
            model=config.model,
            tools=tools,
            system_prompt=MACRO_TRIAGE_SYSTEM,
        )

        print("  agent exploring...", flush=True)
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=MACRO_TRIAGE_USER)]},
            config={"recursion_limit": 15},
        )
        print("  agent finished", flush=True)

        final_content = result["messages"][-1].content
        parsed = _safe_json_loads(
            final_content,
            {
                "macro_stats": {"summary": "LLM output parse failed", "highlights": []},
                "suspicious_targets": [],
            },
        )
        suspicious_targets = _normalize_suspicious_targets(
            parsed.get("suspicious_targets", [])
        )
        suspicious_targets = limit_list(suspicious_targets, 10)
        return {
            "macro_stats": parsed.get("macro_stats", {}),
            "suspicious_targets": suspicious_targets,
        }

    return _node


# ---------------------------------------------------------------------------
# Node 2 — Target Extraction
# ---------------------------------------------------------------------------


def target_extraction_node(config: NodeConfig):
    async def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        user_prompt = TARGET_EXTRACTION_USER.format(
            macro_stats=state["macro_stats"],
            suspicious_targets=state["suspicious_targets"],
        )
        full_text = ""
        async for chunk in config.model.astream(
            [SystemMessage(content=TARGET_EXTRACTION_SYSTEM), HumanMessage(content=user_prompt)]
        ):
            if chunk.content:
                print(chunk.content, end="", flush=True)
                full_text += chunk.content
        print()
        parsed = _safe_json_loads(full_text, {"tshark_filters": []})
        raw_filters = parsed.get("tshark_filters", [])
        filters: List[str] = []
        for filter_expr in raw_filters:
            try:
                filters.append(validate_display_filter(str(filter_expr)))
            except ValueError:
                continue
        if not filters:
            filters = _fallback_filters(state["suspicious_targets"])
            filters = [validate_display_filter(f) for f in filters]
        return {"tshark_filters": limit_list(filters, 10)}

    return _node


# ---------------------------------------------------------------------------
# Node 3 — Micro Deepdive
# ---------------------------------------------------------------------------


def micro_deepdive_node(config: NodeConfig):
    async def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        details: List[Dict[str, Any]] = []
        pcap_path = ensure_pcap_path(state["pcap_path"])
        filters = state["tshark_filters"]
        for idx, display_filter in enumerate(filters):
            print(f"\n  [{idx + 1}/{len(filters)}] {display_filter}", flush=True)
            tools = create_micro_deepdive_tools(
                config.session, pcap_path, config.max_packets
            )
            agent = create_agent(
                model=config.model,
                tools=tools,
                system_prompt=MICRO_DEEPDIVE_SYSTEM,
            )
            user_prompt = MICRO_DEEPDIVE_USER.format(display_filter=display_filter)

            print("    agent exploring...", flush=True)
            result = await agent.ainvoke(
                {"messages": [HumanMessage(content=user_prompt)]},
                config={"recursion_limit": config.max_iterations * 3},
            )
            print("    agent finished", flush=True)

            final_content = result["messages"][-1].content
            parsed = _safe_json_loads(
                final_content,
                {
                    "filter": display_filter,
                    "verdict": "none",
                    "findings": ["LLM output parse failed"],
                    "evidence": [],
                    "confidence": 0.0,
                },
            )
            parsed.setdefault("filter", display_filter)
            details.append(parsed)
            print(
                f"    verdict: {parsed.get('verdict', '?')} "
                f"(confidence {parsed.get('confidence', 0):.2f})"
            )
        return {"micro_details": details}

    return _node


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _is_global_ip(ip_value: str) -> bool:
    try:
        ip_text = validate_ip(ip_value)
        ip_obj = ipaddress.ip_address(ip_text)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Node 4 — Threat Intel
# ---------------------------------------------------------------------------


def threat_intel_node(config: NodeConfig):
    async def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        targets = [t.get("ip") for t in state["suspicious_targets"]]
        ips = [ip for ip in targets if ip and _is_global_ip(ip)]
        if not ips:
            print("  无公网IP，跳过威胁情报查询")
            return {"threat_intel": []}

        print(f"  [intel] querying {len(ips)} public IPs: {', '.join(ips)}")
        providers = "urlhaus,abuseipdb"
        result = await config.session.call_tool(
            "check_ip_threat_intel",
            {"ip_or_filepath": ",".join(ips), "providers": providers},
        )
        if not result.isError and isinstance(result.structuredContent, dict):
            sc = result.structuredContent
            results = sc.get("results", []) if isinstance(sc, dict) else []
            hits = len(results)
            print(f"  [ok] {hits} threat intel hits")
            return {"threat_intel": results}
        print(f"  [warn] query error: {getattr(result, 'content', 'unknown')}")
        return {"threat_intel": []}

    return _node


# ---------------------------------------------------------------------------
# Node 5 — Report Synthesis
# ---------------------------------------------------------------------------


def report_synthesis_node(config: NodeConfig):
    async def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        user_prompt = REPORT_USER.format(
            micro_details=state["micro_details"],
            threat_intel=state["threat_intel"],
        )
        full_text = ""
        async for chunk in config.model.astream(
            [SystemMessage(content=REPORT_SYSTEM), HumanMessage(content=user_prompt)]
        ):
            if chunk.content:
                print(chunk.content, end="", flush=True)
                full_text += chunk.content
        print()
        return {"final_report": full_text}

    return _node
