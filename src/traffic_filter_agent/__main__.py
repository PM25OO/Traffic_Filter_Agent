"""Traffic Filter Agent entry point."""

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Traffic Filter Agent")
    parser.add_argument("--pcap", type=str, help="Path to a PCAP file to analyze")
    parser.add_argument("--model", type=str, default=os.getenv("OPENAI_MODEL", "gpt-4o"),
                        help="LLM model name")
    parser.add_argument("--temperature", type=float, default=0,
                        help="LLM temperature for deterministic outputs")
    args = parser.parse_args()

    print(f"Traffic Filter Agent starting with model={args.model}")
    # TODO: Build and invoke the graph with args
    return 0


if __name__ == "__main__":
    sys.exit(main())
