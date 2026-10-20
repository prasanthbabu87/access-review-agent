"""Identity data store and deterministic access checks.

Every flag is produced by plain Python against HR, application and policy data,
so results are reproducible. The agent decides what to do about each flag.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

CHECKS = {
    "terminated_with_access": "Active application accounts belonging to employees terminated in HR",
    "orphan_accounts": "Human accounts with no matching HR record, and service accounts with no named owner",
    "sod_conflicts": "Accounts holding role combinations prohibited by the segregation of duties ruleset",
    "excess_privilege": "Roles not permitted for the user's department under the role matrix (least privilege)",
    "dormant_accounts": "Accounts with no login within the dormancy threshold",
}


def _d(value: str) -> date | None:
    return date.fromisoformat(value) if value else None


@dataclass
class AccessStore:
    data_dir: Path
    policy: dict = field(init=False)
    employees: dict[str, dict] = field(init=False)
    accounts: dict[str, dict] = field(init=False)

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.policy = json.loads((self.data_dir / "access_policy.json").read_text())
        with open(self.data_dir / "hr_roster.csv", newline="") as f:
            self.employees = {r["employee_id"]: r for r in csv.DictReader(f)}
        with open(self.data_dir / "app_users.csv", newline="") as f:
            self.accounts = {}
            for r in csv.DictReader(f):
                r["roles"] = [x for x in r["roles"].split(";") if x]
                self.accounts[r["user_id"]] = r

    @property
    def as_of(self) -> date:
        return _d(self.policy["review_period_end"])

    def scope(self) -> dict:
        human = sum(a["account_type"] == "human" for a in self.accounts.values())
        return {
            "application": self.policy["application"],
            "review_period_end": self.policy["review_period_end"],
            "accounts": len(self.accounts),
            "human_accounts": human,
            "service_accounts": len(self.accounts) - human,
            "hr_employees": len(self.employees),
            "checks_available": CHECKS,
            "role_descriptions": self.policy["role_descriptions"],
            "sod_rules": self.policy["sod_rules"],
            "dormancy_threshold_days": self.policy["dormancy_threshold_days"],
        }

    def run_check(self, check: str) -> dict:
        if check not in CHECKS:
            raise ValueError(f"Unknown check {check!r}; valid: {list(CHECKS)}")
        flags = getattr(self, f"_{check}")()
        return {"check": check, "description": CHECKS[check], "accounts_reviewed": len(self.accounts),
                "flagged": len(flags), "results": flags}

    # ----- checks --------------------------------------------------------
    def _terminated_with_access(self) -> list[dict]:
        out = []
        for a in self.accounts.values():
            emp = self.employees.get(a["employee_id"])
            if emp and emp["status"] == "terminated":
                term, last = _d(emp["termination_date"]), _d(a["last_login"])
                used_after = bool(last and last > term)
                out.append({"user_id": a["user_id"], "employee": emp["name"], "termination_date": emp["termination_date"],
                            "last_login": a["last_login"], "roles": a["roles"], "login_after_termination": used_after,
                            "detail": f"Terminated {emp['termination_date']}, account still active"
                                      + (f"; LOGGED IN AFTER TERMINATION on {a['last_login']}" if used_after else "")})
        return out

    def _orphan_accounts(self) -> list[dict]:
        out = []
        for a in self.accounts.values():
            if a["account_type"] == "service":
                if not a["owner_id"] or a["owner_id"] not in self.employees:
                    out.append({"user_id": a["user_id"], "roles": a["roles"], "detail": "Service account has no accountable owner"})
            elif a["employee_id"] not in self.employees:
                why = "no employee ID" if not a["employee_id"] else f"employee ID {a['employee_id']} not found in HR"
                out.append({"user_id": a["user_id"], "roles": a["roles"], "detail": f"Human account with {why}"})
        return out

    def _sod_conflicts(self) -> list[dict]:
        out = []
        for a in self.accounts.values():
            for rule in self.policy["sod_rules"]:
                if set(rule["roles"]) <= set(a["roles"]):
                    out.append({"user_id": a["user_id"], "rule": rule["id"], "conflicting_roles": rule["roles"],
                                "detail": f"{' + '.join(rule['roles'])}: {rule['risk']}"})
        return out

    def _excess_privilege(self) -> list[dict]:
        out = []
        matrix = self.policy["role_matrix"]
        for a in self.accounts.values():
            emp = self.employees.get(a["employee_id"])
            if a["account_type"] != "human" or not emp or emp["status"] != "active":
                continue  # covered by other checks
            allowed = set(matrix.get(emp["department"], []))
            extra = [r for r in a["roles"] if r not in allowed]
            if extra:
                out.append({"user_id": a["user_id"], "department": emp["department"], "title": emp["title"],
                            "excess_roles": extra,
                            "detail": f"{emp['title']} in {emp['department']} holds {', '.join(extra)} not permitted for the department"})
        return out

    def _dormant_accounts(self) -> list[dict]:
        limit = self.policy["dormancy_threshold_days"]
        out = []
        for a in self.accounts.values():
            days = (self.as_of - _d(a["last_login"])).days
            if days > limit:
                out.append({"user_id": a["user_id"], "last_login": a["last_login"], "days_inactive": days,
                            "detail": f"No login for {days} days (threshold {limit})"})
        return out

    # ----- drill-down ----------------------------------------------------
    def user_profile(self, user_id: str) -> dict:
        a = self.accounts.get(user_id)
        if not a:
            return {"error": f"{user_id} not found in {self.policy['application']}"}
        emp = self.employees.get(a["employee_id"]) or self.employees.get(a["owner_id"])
        mgr = self.employees.get(emp["manager_id"]) if emp else None
        return {
            "account": a,
            "hr_record": emp or "NO HR RECORD",
            "manager": f"{mgr['name']} ({mgr['employee_id']})" if mgr else None,
            "role_descriptions": {r: self.policy["role_descriptions"].get(r) for r in a["roles"]},
            "roles_permitted_for_department": self.policy["role_matrix"].get(emp["department"]) if emp else None,
        }

    def manager_for(self, user_id: str) -> str:
        a = self.accounts[user_id]
        emp = self.employees.get(a["employee_id"]) or self.employees.get(a["owner_id"])
        if emp and emp["manager_id"] in self.employees:
            return self.employees[emp["manager_id"]]["name"]
        return "Application owner (no HR manager)"
