"""Review state: remediation decisions, guardrails, and outputs
(an audit report plus a manager certification sheet)."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .access import CHECKS, AccessStore

ACTIONS = ("revoke_account", "remove_roles", "review_with_manager", "accept_with_justification")
RISK = ("High", "Medium", "Low")


@dataclass
class Decision:
    user_id: str
    action: str
    risk: str
    rationale: str
    roles_to_remove: list[str]
    issues: list[str]


@dataclass
class Review:
    store: AccessStore
    check_results: dict[str, dict] = field(default_factory=dict)
    decisions: dict[str, Decision] = field(default_factory=dict)
    summary: str = ""
    finalized: bool = False

    def flags_by_user(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for check, res in self.check_results.items():
            for r in res["results"]:
                out.setdefault(r["user_id"], []).append(f"{check}: {r['detail']}")
        return out

    def record(self, user_id: str, action: str, risk: str, rationale: str, roles_to_remove: list[str] | None = None) -> str:
        flags = self.flags_by_user()
        if user_id not in flags:
            raise ValueError(f"{user_id} was not flagged by any check run so far; decisions are only recorded for flagged accounts.")
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        if risk not in RISK:
            raise ValueError(f"risk must be one of {RISK}")
        roles_to_remove = roles_to_remove or []
        if action == "remove_roles":
            held = set(self.store.accounts[user_id]["roles"])
            if not roles_to_remove or not set(roles_to_remove) <= held:
                raise ValueError(f"remove_roles needs roles the user actually holds: {sorted(held)}")
        if action == "accept_with_justification" and risk == "High":
            raise ValueError("High-risk access cannot be accepted by the agent; use review_with_manager to escalate.")
        self.decisions[user_id] = Decision(user_id, action, risk, rationale, roles_to_remove, flags[user_id])
        return f"Decision recorded for {user_id}: {action}"

    def undecided(self) -> list[str]:
        return sorted(set(self.flags_by_user()) - set(self.decisions))

    def finalize(self, summary: str) -> None:
        missing = sorted(set(CHECKS) - set(self.check_results))
        if missing:
            raise ValueError(f"Cannot finalize: checks not run: {missing}")
        if self.undecided():
            raise ValueError(f"Cannot finalize: flagged accounts without a decision: {self.undecided()}")
        self.summary, self.finalized = summary, True

    # ----- outputs -------------------------------------------------------
    def write_certification_csv(self, path: Path) -> None:
        order = {r: i for i, r in enumerate(RISK)}
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["user_id", "risk", "recommended_action", "roles_to_remove", "issues", "rationale",
                        "certifying_manager", "manager_decision", "manager_comments"])
            for d in sorted(self.decisions.values(), key=lambda d: (order[d.risk], d.user_id)):
                w.writerow([d.user_id, d.risk, d.action, ";".join(d.roles_to_remove), " | ".join(d.issues),
                            d.rationale, self.store.manager_for(d.user_id), "", ""])

    def to_markdown(self) -> str:
        s = self.store.scope()
        flagged = self.flags_by_user()
        lines = [
            f"# User Access Review — {s['application']}",
            "",
            f"**As of:** {s['review_period_end']}  ",
            f"**Prepared:** {datetime.now():%Y-%m-%d %H:%M} by access-review-agent (AI-assisted, requires reviewer sign-off)",
            "",
            f"**Population:** {s['accounts']} accounts ({s['human_accounts']} human, {s['service_accounts']} service), "
            f"{s['hr_employees']} HR records. **Accounts flagged:** {len(flagged)}.",
            "",
            "## 1. Checks performed",
            "",
            "| Check | Description | Flagged |",
            "|---|---|---:|",
        ]
        for c, desc in CHECKS.items():
            r = self.check_results.get(c)
            lines.append(f"| `{c}` | {desc} | {r['flagged'] if r else 'not run'} |")

        order = {r: i for i, r in enumerate(RISK)}
        counts = {r: sum(d.risk == r for d in self.decisions.values()) for r in RISK}
        lines += ["", "## 2. Remediation decisions", "",
                  f"High: **{counts['High']}** · Medium: **{counts['Medium']}** · Low: **{counts['Low']}**", "",
                  "| Risk | Account | Action | Roles to remove | Rationale |", "|---|---|---|---|---|"]
        for d in sorted(self.decisions.values(), key=lambda d: (order[d.risk], d.user_id)):
            lines.append(f"| {d.risk} | `{d.user_id}` | {d.action.replace('_', ' ')} | "
                         f"{', '.join(d.roles_to_remove) or '—'} | {d.rationale} |")

        lines += ["", "## 3. Issue detail", ""]
        for uid in sorted(flagged):
            lines.append(f"- **`{uid}`**")
            lines += [f"  - {issue}" for issue in flagged[uid]]
        lines += ["", "## 4. Summary", "", self.summary or "_Not finalized._", "",
                  "_Manager certification sheet: `certification.csv`._", ""]
        return "\n".join(lines)
