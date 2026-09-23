"""AgentLedger — Sprint 4 end-to-end demo.

Run:  python demo.py

Sprint 4 makes the audit log evidence-grade:
  1. Calls in a task share a trace_id / run_id (distributed-trace shape).
  2. Each event's head is anchored to an external WORM witness.
  3. The log verifies — chain + signatures + anchor.
  4. A MID-CHAIN edit is caught by the hash chain.
  5. A TRUNCATION (delete the tail) is caught by the anchor — the case a plain
     hash chain accepts.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from agents.identity import new_agent
from agents.intent import new_intent
from audit.anchor import WormAnchor
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_evidence, verify_log
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
ANCHOR_PATH = DATA / "worm_anchor.jsonl"  # in prod: Azure Blob w/ immutability policy


def banner(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")


def show(res) -> None:
    colour = {"ALLOW": "\033[32m", "APPROVAL": "\033[33m", "DENY": "\033[31m"}[res.decision.value]
    ev = res.event
    print(f"  {colour}{res.decision.value:<8}\033[0m {res.outcome:<16} [{res.stage}] {res.reason}")
    print(f"           trace={ev.trace_id[:14]}… run={ev.run_id[:12]}… seq={ev.seq}")


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
    if LOG_PATH.exists():
        LOG_PATH.unlink()
    if ANCHOR_PATH.exists():
        ANCHOR_PATH.unlink()

    private, public = load_or_create_keypair(KEY_PATH)
    anchor = WormAnchor(ANCHOR_PATH)
    auth = AuthService()
    policy = PolicyEngine(yaml.safe_load((HERE / "policy" / "policy.yaml").read_text()))
    audit = AuditLog(LOG_PATH, private, anchor=anchor)  # <- audit now anchors each head
    gateway = Gateway(auth, build_registry(), policy, audit)

    bot = new_agent("triage-bot", roles=["operator"])
    token = auth.issue(bot, scopes=["files:read", "files:write", "mail:read", "mail:send"])

    # One task = one run = one shared trace across every call in it.
    run = new_run(bot.agent_id)
    investigate = new_intent("investigate-incident", "read incident reports",
                             allowed_tools=["read_file", "list_files"])
    banner(f"Run started  trace={run.trace_id[:14]}…  run={run.run_id[:12]}…")

    print("\n  call 1 — list the reports")
    show(gateway.handle(token, "list_files", intent=investigate, run=run))
    print("\n  call 2 — read a report")
    show(gateway.handle(token, "read_file", intent=investigate, run=run, path="/reports/q3-summary.txt"))
    print("\n  call 3 — read outside /reports (denied, but still traced + recorded)")
    show(gateway.handle(token, "read_file", intent=investigate, run=run, path="/etc/passwd"))

    banner("Verify evidence — internal chain + signatures + external anchor")
    print(f"  {verify_evidence(LOG_PATH, public, anchor)}")

    banner("Attack A — edit an event in the middle of the log")
    lines = LOG_PATH.read_text().splitlines()
    saved = list(lines)
    lines[0] = lines[0].replace("list_files", "delete_file")
    LOG_PATH.write_text("\n".join(lines) + "\n")
    print(f"  {verify_evidence(LOG_PATH, public, anchor)}")
    LOG_PATH.write_text("\n".join(saved) + "\n")  # restore

    banner("Attack B — truncate: delete the LAST event")
    lines = LOG_PATH.read_text().splitlines()
    truncated = lines[:-1]
    LOG_PATH.write_text("\n".join(truncated) + "\n")
    print(f"  chain-only verify (blind to truncation): {verify_log(LOG_PATH, public)}")
    print(f"  evidence verify (anchor catches it):     {verify_evidence(LOG_PATH, public, anchor)}")

    print("\n\033[1mSprint 4 done:\033[0m traced, chained, signed, WORM-anchored — "
          "edits AND truncation are both detectable.\n")


if __name__ == "__main__":
    main()
