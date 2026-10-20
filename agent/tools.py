"""Tool definitions exposed to the model, and the dispatcher that runs them."""
from __future__ import annotations

import json
from typing import Any

from .access import CHECKS, AccessStore
from .review import ACTIONS, RISK, Review

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "get_review_scope",
        "description": "Return the application in scope, population counts, available checks, role descriptions, SoD rules and dormancy threshold. Call this first.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_check",
        "description": "Run one deterministic access check across ALL accounts and return every flagged account.",
        "input_schema": {
            "type": "object",
            "properties": {"check": {"type": "string", "enum": list(CHECKS)}},
            "required": ["check"],
        },
    },
    {
        "name": "get_user_profile",
        "description": "Get the joined view for one account: application roles, HR record, manager, and roles permitted for the user's department. Use it to decide remediation.",
        "input_schema": {
            "type": "object",
            "properties": {"user_id": {"type": "string"}},
            "required": ["user_id"],
        },
    },
    {
        "name": "record_decision",
        "description": (
            "Record ONE remediation decision per flagged account, considering ALL of its issues together. "
            "Calling again for the same account replaces the earlier decision. Actions: revoke_account (disable entirely), "
            "remove_roles (list the specific roles), review_with_manager (needs business confirmation), "
            "accept_with_justification (only Medium/Low risk with a documented reason)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "action": {"type": "string", "enum": list(ACTIONS)},
                "risk": {"type": "string", "enum": list(RISK)},
                "rationale": {"type": "string", "description": "One or two sentences citing the facts"},
                "roles_to_remove": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["user_id", "action", "risk", "rationale"],
        },
    },
    {
        "name": "finalize_review",
        "description": "Close the review with an executive summary. Only possible once all checks are run and every flagged account has a decision.",
        "input_schema": {
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        },
    },
]


class Toolbox:
    def __init__(self, store: AccessStore):
        self.store = store
        self.review = Review(store)

    def run(self, name: str, args: dict) -> tuple[str, bool]:
        """Execute a tool. Returns (json_result, is_error)."""
        handler = getattr(self, f"_{name}", None)
        if handler is None:
            return json.dumps({"error": f"Unknown tool {name}"}), True
        try:
            return json.dumps(handler(**args), indent=1), False
        except (ValueError, TypeError) as exc:
            return json.dumps({"error": str(exc)}), True

    def _get_review_scope(self) -> dict:
        return self.store.scope()

    def _run_check(self, check: str) -> dict:
        result = self.store.run_check(check)
        self.review.check_results[check] = result
        return result

    def _get_user_profile(self, user_id: str) -> dict:
        return self.store.user_profile(user_id)

    def _record_decision(self, user_id, action, risk, rationale, roles_to_remove=None) -> dict:
        status = self.review.record(user_id, action, risk, rationale, roles_to_remove)
        return {"status": status, "flagged_accounts_without_decision": self.review.undecided()}

    def _finalize_review(self, summary: str) -> dict:
        self.review.finalize(summary)
        return {"status": "Review finalized", "decisions": len(self.review.decisions)}
