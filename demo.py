"""AgentLedger — Sprint 5 end-to-end demo.

Run:  python demo.py   (then open the dashboard.html it writes)

Sprint 5 adds the human in the loop and the console:
  1. A consequential action is HELD for approval — not run.
  2. A person APPROVES it — now it executes, audited as "approved by <person>".
  3. Another is DENIED — blocked, audited as "denied by <person>".
  4. A control-plane dashboard is generated from the audit log.
  5. The evidence still verifies (chain + signatures + anchor).
"""
from __future__ import annotations

from pathlib import Path

import yaml

import dashboard
from agents.identity import new_agent
from agents.intent import new_intent
from approvals.store import ApprovalService
from audit.anchor import WormAnchor
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_evidence
from audit.trace import new_run
from gateway.auth import AuthService
from gateway.gateway import Gateway
from gateway.registry import ToolRegistry, ToolSpec
from mcp_servers.fake_mcp import FakeMCPServer
from mcp_servers.mail_mcp import MailMCPServer
from policy.engine import PolicyEngine

HERE = Path(__file__).parent
DATA = HERE / ".agentledger"
LOG_PATH = DATA / "audit.jsonl"
KEY_PATH = DATA / "audit_signing_key.pem"
ANCHOR_PATH = DATA / "worm_anchor.jsonl"
DASH_PATH = HERE / "dashboard.html"


def banner(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")


def show(res) -> None:
    colour = {"ALLOW": "\033[32m", "APPROVAL": "\033[33m", "DENY": "\033[31m"}[res.decision.value]
    print(f"  {colour}{res.decision.value:<8}\033[0m {res.outcome:<16} [{res.stage}] {res.reason}")


def build_registry() -> ToolRegistry:
    files, mail = FakeMCPServer(), MailMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("list_files", "List files", "files:read", files))
    reg.register(ToolSpec("read_file", "Read a file", "files:read", files))
    reg.register(ToolSpec("delete_file", "Delete a file", "files:write", files))
    reg.register(ToolSpec("list_inbox", "List inbox", "mail:read", mail))
    reg.register(ToolSpec("send_email", "Send an email", "mail:send", mail))
    return reg


def main() -> None:
    for p in (LOG_PATH, ANCHOR_PATH):
        if p.exists():
            p.unlink()

    private, public = load_or_create_keypair(KEY_PATH)
    anchor = WormAnchor(ANCHOR_PATH)
    registry = build_registry()
    auth = AuthService()
    policy = PolicyEngine(yaml.safe_load((HERE / "policy" / "policy.yaml").read_text()))
    audit = AuditLog(LOG_PATH, private, anchor=anchor)
    approvals = ApprovalService(registry, audit)
    gateway = Gateway(auth, registry, policy, audit, approval=approvals)

    bot = new_agent("triage-bot", roles=["operator"])
    token = auth.issue(bot, scopes=["files:read", "files:write", "mail:read", "mail:send"])
    run = new_run(bot.agent_id)
    notify = new_intent("notify-team", "email the team; tidy old reports",
                        allowed_tools=["send_email", "delete_file", "read_file"])

    banner("A routine read flows straight through (no approval)")
    show(gateway.handle(token, "read_file", intent=notify, run=run, path="/reports/q3-summary.txt"))

    banner("A consequential action is HELD for a human")
    r1 = gateway.handle(token, "send_email", intent=notify, run=run, to="alex@company.com", subject="incident update")
    show(r1)
    r2 = gateway.handle(token, "delete_file", intent=notify, run=run, path="/reports/old-draft.txt")
    show(r2)

    banner(f"Approvals queue: {len(approvals.pending())} pending")
    for req in approvals.pending():
        print(f"  · {req.id}  {req.tool}({req.params})  — {req.reason}")

    banner("Security lead decides")
    out1 = approvals.approve(r1.approval_id, "security-lead@company.com")
    print(f"  APPROVED {r1.approval_id}: send_email -> executed  result={out1.result!r}")
    out2 = approvals.deny(r2.approval_id, "security-lead@company.com")
    print(f"  DENIED   {r2.approval_id}: delete_file -> blocked")

    banner("Evidence still verifies")
    print(f"  {verify_evidence(LOG_PATH, public, anchor)}")

    dashboard.generate(LOG_PATH, approvals.all(), DASH_PATH)
    banner(f"Dashboard written -> {DASH_PATH.name}  (open it in a browser)")

    print("\n\033[1mSprint 5 done:\033[0m consequential actions held for a human, "
          "decisions audited, and a control-plane dashboard.\n")


if __name__ == "__main__":
    main()
