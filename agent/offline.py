"""Offline demo mode: a rule-based planner that drives the SAME tools the LLM uses.

Lets anyone run the full workflow without an API key, and gives a baseline to
compare the LLM's decisions against.
"""
from __future__ import annotations

import json

from .access import CHECKS
from .llm_agent import AuditTrail
from .tools import Toolbox

TRANSACTIONAL = {"AP_CLERK", "VENDOR_MAINT", "PAY_APPROVER", "GL_POSTER", "GL_APPROVER", "SYS_ADMIN"}


def decide(user_id: str, results: dict, profile: dict) -> dict:
    """Apply the review policy to all issues for one account."""
    def hits(check):
        return [r for r in results[check]["results"] if r["user_id"] == user_id]

    roles = profile["account"]["roles"]
    permitted = set(profile["roles_permitted_for_department"] or [])

    if t := hits("terminated_with_access"):
        t = t[0]
        note = " Login after termination - escalate to security as a potential incident." if t["login_after_termination"] else ""
        return dict(action="revoke_account", risk="High",
                    rationale=f"Employee terminated {t['termination_date']} but account remains active.{note}")
    if o := hits("orphan_accounts"):
        if profile["account"]["account_type"] == "service":
            return dict(action="review_with_manager", risk="High",
                        rationale=f"{o[0]['detail']}; holds {', '.join(roles)}. Assign an accountable owner or disable.")
        return dict(action="revoke_account", risk="High",
                    rationale=f"{o[0]['detail']}; holds {', '.join(roles)}. No accountable individual.")
    if sod := hits("sod_conflicts"):
        conflicting = {r for s in sod for r in s["conflicting_roles"]}
        remove = sorted(conflicting - permitted)
        rules = ", ".join(s["rule"] for s in sod)
        if remove:
            return dict(action="remove_roles", risk="High", roles_to_remove=remove,
                        rationale=f"SoD conflict ({rules}); {', '.join(remove)} not permitted for the user's department.")
        return dict(action="review_with_manager", risk="High",
                    rationale=f"SoD conflict ({rules}) between roles both permitted for the department; manager to split duties or document a compensating control.")
    if ex := hits("excess_privilege"):
        return dict(action="remove_roles", risk="Medium", roles_to_remove=ex[0]["excess_roles"],
                    rationale=ex[0]["detail"] + ".")
    if dm := hits("dormant_accounts"):
        risky = bool(set(roles) & TRANSACTIONAL)
        return dict(action="review_with_manager", risk="Medium" if risky else "Low",
                    rationale=f"{dm[0]['detail']}; " + ("holds transactional roles - disable if no longer needed." if risky else "read-only access."))
    raise ValueError(f"{user_id} has no flags")


def run_offline(toolbox: Toolbox, trail: AuditTrail, verbose: bool = True) -> Toolbox:
    def call(name, **args):
        out, err = toolbox.run(name, args)
        trail.log("tool_call", tool=name, input=args, is_error=err, output_preview=out[:300])
        if verbose:
            print(f"  -> {name}({json.dumps(args)[:80]}) [{'ERROR' if err else 'ok'}]")
        return json.loads(out)

    trail.log("run_started", model="offline-rules")
    call("get_review_scope")
    results = {c: call("run_check", check=c) for c in CHECKS}
    for uid in sorted(toolbox.review.flags_by_user()):
        profile = call("get_user_profile", user_id=uid)
        call("record_decision", user_id=uid, **decide(uid, results, profile))

    d = toolbox.review.decisions.values()
    high = sum(x.risk == "High" for x in d)
    revoke = sum(x.action == "revoke_account" for x in d)
    leavers = results["terminated_with_access"]["results"]
    post_term = sum(r["login_after_termination"] for r in leavers)
    call("finalize_review", summary=(
        f"{len(d)} of {len(toolbox.store.accounts)} accounts require action ({high} High risk), including "
        f"{revoke} account revocations. {len(leavers)} terminated employees retained access ({post_term} with a "
        "login after the termination date), pointing to a gap in the HR-to-IT leaver process. SoD conflicts and excess "
        "roles in payment and journal processes indicate role assignments are not checked against the role "
        "matrix at provisioning. Recommend automating leaver de-provisioning from the HR system and adding "
        "an SoD check to the access request workflow."))
    trail.log("run_ended", stop_reason="review_finalized")
    return toolbox
