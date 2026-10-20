import csv
import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from agent.access import AccessStore
from agent.llm_agent import AuditTrail, run_agent
from agent.offline import run_offline
from agent.tools import Toolbox

DATA = Path(__file__).parent.parent / "data"


@pytest.fixture
def toolbox():
    return Toolbox(AccessStore(DATA))


def flagged(check):
    return sorted({r["user_id"] for r in AccessStore(DATA).run_check(check)["results"]})


# ---------- deterministic checks ----------
@pytest.mark.parametrize("check,expected", [
    ("terminated_with_access", ["dnair", "rjoseph", "rmalhotra"]),
    ("orphan_accounts", ["jdsouza", "svc_bankfeed", "temp_admin"]),
    ("sod_conflicts", ["fali", "kgeorge", "miyer", "nkumar", "temp_admin"]),
    ("excess_privilege", ["averma", "fali", "kgeorge", "miyer"]),
    ("dormant_accounts", ["phegde", "rjoseph", "sdas"]),
])
def test_checks(check, expected):
    assert flagged(check) == expected


def test_login_after_termination_detected():
    res = AccessStore(DATA).run_check("terminated_with_access")["results"]
    assert {r["user_id"] for r in res if r["login_after_termination"]} == {"dnair"}


def test_service_account_with_owner_not_orphan():
    assert "svc_batch" not in flagged("orphan_accounts")


# ---------- guardrails ----------
def test_decision_requires_flag(toolbox):
    toolbox.run("run_check", {"check": "dormant_accounts"})
    out, err = toolbox.run("record_decision", {"user_id": "vshah", "action": "revoke_account", "risk": "High", "rationale": "x"})
    assert err and "not flagged" in out


def test_remove_roles_must_be_held(toolbox):
    toolbox.run("run_check", {"check": "excess_privilege"})
    out, err = toolbox.run("record_decision", {"user_id": "averma", "action": "remove_roles", "risk": "Medium",
                                               "rationale": "x", "roles_to_remove": ["SYS_ADMIN"]})
    assert err and "actually holds" in out


def test_agent_cannot_accept_high_risk(toolbox):
    toolbox.run("run_check", {"check": "terminated_with_access"})
    out, err = toolbox.run("record_decision", {"user_id": "dnair", "action": "accept_with_justification",
                                               "risk": "High", "rationale": "x"})
    assert err and "cannot be accepted" in out


def test_cannot_finalize_early(toolbox):
    out, err = toolbox.run("finalize_review", {"summary": "done"})
    assert err and "checks not run" in out


# ---------- end-to-end ----------
def test_offline_run(toolbox, tmp_path):
    run_offline(toolbox, AuditTrail(tmp_path / "t.jsonl"), verbose=False)
    r = toolbox.review
    assert r.finalized and len(r.decisions) == 13 and not r.undecided()
    assert r.decisions["dnair"].action == "revoke_account"
    assert r.decisions["miyer"].roles_to_remove == ["PAY_APPROVER"]
    assert r.decisions["nkumar"].action == "review_with_manager"
    r.write_certification_csv(tmp_path / "c.csv")
    rows = list(csv.DictReader(open(tmp_path / "c.csv")))
    assert len(rows) == 13 and rows[0]["risk"] == "High"
    assert next(x for x in rows if x["user_id"] == "miyer")["certifying_manager"] == "Anita Rao"


class FakeClient:
    def __init__(self, turns):
        self.turns, self.calls = list(turns), []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        blocks, stop = self.turns.pop(0)
        return NS(content=blocks, stop_reason=stop)


def tool(id_, name, **inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


def test_llm_loop(toolbox, tmp_path):
    client = FakeClient([
        ([tool("a", "run_check", check="terminated_with_access")], "tool_use"),
        ([tool("b", "record_decision", user_id="dnair", action="revoke_account", risk="High", rationale="leaver"),
          tool("c", "record_decision", user_id="ghost", action="revoke_account", risk="High", rationale="x")], "tool_use"),
        ([NS(type="text", text="stopping")], "end_turn"),
    ])
    trail = AuditTrail(tmp_path / "t.jsonl")
    run_agent(toolbox, trail, client=client, verbose=False)
    results = client.calls[2]["messages"][-1]["content"]
    assert [r["is_error"] for r in results] == [False, True]
    assert "dnair" in toolbox.review.decisions
    events = [json.loads(l)["event"] for l in trail.path.read_text().splitlines()]
    assert events.count("tool_call") == 3
