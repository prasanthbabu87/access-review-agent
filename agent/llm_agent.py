"""Claude tool-use loop with a full audit trail of every agent action."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .tools import TOOL_SPECS, Toolbox

DEFAULT_MODEL = os.environ.get("ACCESS_AGENT_MODEL", "claude-sonnet-5-5")

SYSTEM_PROMPT = """You are an IT auditor running a periodic user access review (UAR) for a \
financially significant application. Work methodically:
1. Call get_review_scope.
2. Run EVERY check with run_check.
3. For each flagged account, consider ALL of its issues together. Use get_user_profile when \
you need the HR record, manager or permitted roles to decide.
4. Record exactly one decision per flagged account with record_decision:
   - Terminated users and orphaned human accounts -> revoke_account, High. A login after the \
termination date is a potential security incident; say so.
   - Service accounts without an owner -> review_with_manager, High (assign an owner).
   - SoD conflicts -> remove_roles for the role NOT permitted by the user's department; if both \
roles are permitted for the department, review_with_manager (High) for a compensating control.
   - Excess privilege -> remove_roles, Medium.
   - Dormant only -> review_with_manager; Medium if the account holds transactional roles, \
Low if read-only.
5. When every flagged account has a decision, call finalize_review with a short executive \
summary: counts by risk, the most serious issues, and root-cause themes (e.g. leaver process).
Only state facts returned by tools. Never invent users, roles or dates."""


class AuditTrail:
    """Append-only JSONL log of every agent step — the agent's own audit trail."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("")

    def log(self, event: str, **data) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, **data}
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")


def run_agent(toolbox: Toolbox, trail: AuditTrail, client=None, model: str = DEFAULT_MODEL,
              max_turns: int = 60, verbose: bool = True) -> Toolbox:
    if client is None:
        import anthropic
        client = anthropic.Anthropic()

    messages = [{"role": "user", "content": "Perform the quarterly user access review for this application."}]
    trail.log("run_started", model=model)

    for turn in range(1, max_turns + 1):
        response = client.messages.create(
            model=model, max_tokens=4096, system=SYSTEM_PROMPT, tools=TOOL_SPECS, messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        for block in response.content:
            if block.type == "text" and block.text.strip():
                trail.log("reasoning", turn=turn, text=block.text)
                if verbose:
                    print(f"\n[agent] {block.text.strip()}")

        if response.stop_reason != "tool_use":
            trail.log("run_ended", turn=turn, stop_reason=response.stop_reason)
            break

        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            output, is_error = toolbox.run(block.name, dict(block.input))
            trail.log("tool_call", turn=turn, tool=block.name, input=block.input, is_error=is_error,
                      output_preview=output[:300])
            if verbose:
                print(f"  -> {block.name}({json.dumps(block.input)[:80]}) [{'ERROR' if is_error else 'ok'}]")
            results.append({"type": "tool_result", "tool_use_id": block.id, "content": output, "is_error": is_error})
        messages.append({"role": "user", "content": results})

        if toolbox.review.finalized:
            trail.log("run_ended", turn=turn, stop_reason="review_finalized")
            break
    else:
        trail.log("run_ended", stop_reason="max_turns_reached")

    return toolbox
