"""Traffic Filter Agent entry point."""

import argparse
import asyncio
import os
import sys
import time

from dotenv import load_dotenv

from .graph import build_graph
from .model_provider import create_chat_model
from .security import ensure_pcap_path
from .state import TrafficAnalysisState
from .tools import build_mcp_client


NODE_LABELS = {
    "macro_triage": "宏观流量分诊",
    "target_extraction": "过滤器生成",
    "micro_deepdive": "深度包分析",
    "threat_intel": "威胁情报查询",
    "report_synthesis": "审计报告生成",
}


async def main() -> int:
    load_dotenv(override=False)

    parser = argparse.ArgumentParser(description="Traffic Filter Agent")
    parser.add_argument(
        "--pcap", type=str, required=True, help="Path to a PCAP file to analyze"
    )
    parser.add_argument(
        "--provider",
        type=str,
        default=os.getenv("MODEL_PROVIDER", "deepseek"),
        choices=["deepseek", "openai"],
        help="LLM provider (deepseek or openai)",
    )
    default_model = os.getenv("MODEL_NAME")
    if not default_model:
        if os.getenv("MODEL_PROVIDER", "deepseek") == "deepseek":
            default_model = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")
        else:
            default_model = os.getenv("OPENAI_MODEL", "gpt-4o")
    parser.add_argument(
        "--model",
        type=str,
        default=default_model,
        help="LLM model name",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=None,
        help="Override API base URL for the provider",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0,
        help="LLM temperature for deterministic outputs",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=100,
        help="Max packets per filter (hard-capped at 100)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=5,
        help="Max iterations for micro deepdive loop",
    )
    args = parser.parse_args()

    provider = args.provider.lower()
    model = create_chat_model(
        provider=provider,
        model_name=args.model,
        temperature=args.temperature,
        base_url=args.base_url,
    )

    pcap_path = ensure_pcap_path(args.pcap)
    max_packets = min(args.max_packets, 100)

    print(f"Traffic Filter Agent | provider={provider} model={args.model}")
    print(f"PCAP: {pcap_path}")

    mcp_client = build_mcp_client()
    async with mcp_client.session("wireshark") as session:
        graph = await build_graph(
            model=model,
            session=session,
            max_packets=max_packets,
            max_iterations=args.max_iterations,
        )
        initial_state: TrafficAnalysisState = {
            "pcap_path": pcap_path,
            "macro_stats": {},
            "suspicious_targets": [],
            "tshark_filters": [],
            "micro_details": [],
            "threat_intel": [],
            "final_report": "",
        }

        t0 = time.time()
        i = 0
        async for event in graph.astream(initial_state, stream_mode="updates"):
            node = list(event.keys())[0]
            i += 1
            elapsed = time.time() - t0
            label = NODE_LABELS.get(node, node)
            print(f"\n{'─' * 50}")
            print(f"[{i}/5] {label} ({elapsed:.1f}s)")
            print(f"{'─' * 50}")

        total = time.time() - t0
        print(f"\n{'=' * 50}")
        print(f"总耗时: {total:.1f}s")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
