"""Traffic Filter Agent entry point."""

import argparse
import os
import sys

from .graph import build_graph
from .security import ensure_pcap_path
from .state import TrafficAnalysisState


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def main() -> int:
    _load_dotenv()
    parser = argparse.ArgumentParser(description="Traffic Filter Agent")
    parser.add_argument("--pcap", type=str, required=True, help="Path to a PCAP file to analyze")
    parser.add_argument("--model", type=str, default=os.getenv("OPENAI_MODEL", "gpt-4o"),
                        help="LLM model name")
    parser.add_argument("--temperature", type=float, default=0,
                        help="LLM temperature for deterministic outputs")
    parser.add_argument("--max-packets", type=int, default=100,
                        help="Max packets per filter (hard-capped at 100)")
    parser.add_argument("--max-iterations", type=int, default=5,
                        help="Max iterations for micro deepdive loop")
    args = parser.parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is required. Set it in the environment or .env.")

    pcap_path = ensure_pcap_path(args.pcap)
    max_packets = min(args.max_packets, 100)

    print(f"Traffic Filter Agent starting with model={args.model}")
    graph = build_graph(
        model_name=args.model,
        temperature=args.temperature,
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
    result = graph.invoke(initial_state)
    print(result.get("final_report", ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
