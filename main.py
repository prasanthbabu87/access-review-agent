"""CLI entry point.

    python main.py              # uses Claude if ANTHROPIC_API_KEY is set, else offline demo
    python main.py --offline    # rule-based demo, no API key needed
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from agent.access import AccessStore
from agent.llm_agent import DEFAULT_MODEL, AuditTrail, run_agent
from agent.offline import run_offline
from agent.tools import Toolbox

ROOT = Path(__file__).parent


def main() -> None:
    p = argparse.ArgumentParser(description="AI agent for user access reviews")
    p.add_argument("--data", default=ROOT / "data", type=Path)
    p.add_argument("--out", default=ROOT / "output", type=Path)
    p.add_argument("--offline", action="store_true", help="run rule-based demo without an API key")
    p.add_argument("--model", default=DEFAULT_MODEL)
    args = p.parse_args()

    toolbox = Toolbox(AccessStore(args.data))
    trail = AuditTrail(args.out / "agent_audit_trail.jsonl")

    if args.offline or not os.environ.get("ANTHROPIC_API_KEY"):
        print("Running in OFFLINE demo mode (rule-based planner, same tools).")
        run_offline(toolbox, trail)
    else:
        print(f"Running with Claude ({args.model}).")
        run_agent(toolbox, trail, model=args.model)

    review = toolbox.review
    (args.out / "access_review.md").write_text(review.to_markdown())
    review.write_certification_csv(args.out / "certification.csv")
    print(f"\nDecisions: {len(review.decisions)} | finalized: {review.finalized}")
    print(f"Report:        {args.out / 'access_review.md'}")
    print(f"Certification: {args.out / 'certification.csv'}")
    print(f"Audit trail:   {trail.path}")


if __name__ == "__main__":
    main()
