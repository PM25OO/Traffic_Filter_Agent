"""LangGraph nodes for traffic analysis."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Dict, List

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

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
from .mcp_client import WiresharkMCPClient
from .state import TrafficAnalysisState


@dataclass(frozen=True)
class NodeConfig:
    model: BaseChatModel
    mcp: WiresharkMCPClient
    max_packets: int = 100
    max_iterations: int = 5


def _safe_json_loads(payload: str, fallback: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return fallback


def _payload_to_json(payload: Any) -> str:
    if isinstance(payload, dict) and "data" in payload:
        payload = payload.get("data")
    try:
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except TypeError:
        return str(payload)


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


def macro_triage_node(config: NodeConfig):
    def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        pcap_path = ensure_pcap_path(state["pcap_path"])
        protocol_stats = config.mcp.get_protocol_statistics(pcap_path)
        if protocol_stats.get("status") != "success":
            error_message = protocol_stats.get("message", "unknown error")
            protocol_hierarchy = f"error: {error_message}"
            ip_conversations = f"error: {error_message}"
        else:
            protocol_hierarchy = protocol_stats.get("protocol_hierarchy", "")
            ip_conversations = protocol_stats.get("ip_conversations", "")
        prompt = MACRO_TRIAGE_USER.format(
            protocol_hierarchy=protocol_hierarchy,
            ip_conversations=ip_conversations,
        )
        response = config.model.invoke(
            [SystemMessage(content=MACRO_TRIAGE_SYSTEM), HumanMessage(content=prompt)]
        )
        parsed = _safe_json_loads(
            response.content,
            {
                "macro_stats": {"summary": "LLM output parse failed", "highlights": []},
                "suspicious_targets": [],
            },
        )
        suspicious_targets = _normalize_suspicious_targets(
            parsed.get("suspicious_targets", [])
        )
        suspicious_targets = limit_list(suspicious_targets, 10)
        macro_stats = parsed.get("macro_stats", {})
        macro_stats.update(
            {
                "raw_protocol_hierarchy": protocol_hierarchy,
                "raw_ip_conversations": ip_conversations,
            }
        )
        return {
            "macro_stats": macro_stats,
            "suspicious_targets": suspicious_targets,
        }

    return _node


def target_extraction_node(config: NodeConfig):
    def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        prompt = TARGET_EXTRACTION_USER.format(
            macro_stats=state["macro_stats"],
            suspicious_targets=state["suspicious_targets"],
        )
        response = config.model.invoke(
            [
                SystemMessage(content=TARGET_EXTRACTION_SYSTEM),
                HumanMessage(content=prompt),
            ]
        )
        parsed = _safe_json_loads(response.content, {"tshark_filters": []})
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


def micro_deepdive_node(config: NodeConfig):
    def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        details: List[Dict[str, Any]] = []
        pcap_path = ensure_pcap_path(state["pcap_path"])
        for display_filter in state["tshark_filters"]:
            safe_filter = validate_display_filter(display_filter)
            iterations = 0
            while iterations < config.max_iterations:
                iterations += 1
                packets_payload = config.mcp.export_packets_json(
                    pcap_path, safe_filter, config.max_packets
                )
                packets_json = _payload_to_json(packets_payload)
                prompt = MICRO_DEEPDIVE_USER.format(
                    display_filter=safe_filter,
                    packets_json=packets_json,
                )
                response = config.model.invoke(
                    [
                        SystemMessage(content=MICRO_DEEPDIVE_SYSTEM),
                        HumanMessage(content=prompt),
                    ]
                )
                parsed = _safe_json_loads(
                    response.content,
                    {
                        "filter": safe_filter,
                        "verdict": "none",
                        "findings": ["LLM output parse failed"],
                        "evidence": [],
                        "confidence": 0.0,
                    },
                )
                parsed["filter"] = safe_filter
                parsed["iterations"] = iterations
                details.append(parsed)
                break
        return {"micro_details": details}

    return _node


def _is_global_ip(ip_value: str) -> bool:
    try:
        ip_text = validate_ip(ip_value)
        ip_obj = ipaddress.ip_address(ip_text)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
    except Exception:
        return False


def threat_intel_node(config: NodeConfig):
    def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        targets = [t.get("ip") for t in state["suspicious_targets"]]
        ips = [ip for ip in targets if ip and _is_global_ip(ip)]
        if not ips:
            return {"threat_intel": []}

        providers = "urlhaus,abuseipdb"
        result = config.mcp.check_ip_threat_intel(ips, providers)
        if result.get("status") == "success" and isinstance(result.get("results"), list):
            return {"threat_intel": result.get("results", [])}
        return {"threat_intel": [result]}

    return _node


def report_synthesis_node(config: NodeConfig):
    def _node(state: TrafficAnalysisState) -> Dict[str, Any]:
        prompt = REPORT_USER.format(
            micro_details=state["micro_details"],
            threat_intel=state["threat_intel"],
        )
        response = config.model.invoke(
            [SystemMessage(content=REPORT_SYSTEM), HumanMessage(content=prompt)]
        )
        return {"final_report": response.content}

    return _node
