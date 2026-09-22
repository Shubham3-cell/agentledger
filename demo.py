"""AgentLedger — Sprint 1 end-to-end demo.

Run:  python demo.py

It shows the whole spine in one pass:
  1. An agent identity is minted.
  2. A tool call is ALLOWED, executed, and recorded.
  3. A destructive call is held for APPROVAL (not executed) and recorded.
  4. A disallowed call is DENIED by default and recorded.
  5. The audit log verifies — hash chain + Ed25519 signatures all pass.
  6. We tamper with one event and verification catches it.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from agents.identity import new_agent
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_log
from gateway.gateway import Gateway
from mcp_servers.fake_mcp import FakeMCPServer
from policy.engine import PolicyEngine

HERE = Path(__file__).parent
DATA = HERE / ".agentledger"
LOG_PATH = DATA / "audit.jsonl"
KEY_PATH = DATA / "audit_signing_key.pem"


def banner(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")


def show(res) -> None:
    colour = {"ALLOW": "\033[32m", "APPROVAL": "\033[33m", "DENY": "\033[31m"}[res.decision.value]
    print(f"  {colour}{res.decision.value:<8}\033[0m {res.outcome:<16} — {res.reason}")
    if res.result is not None:
        print(f"           result: {res.result!r}")


def main() -> None:
    # Fresh run every time so the demo is reproducible.
    if LOG_PATH.exists():
        LOG_PATH.unlink()

    private, public = load_or_create_keypair(KEY_PATH)
    policy = PolicyEngine(yaml.safe_load((HERE / "policy" / "policy.yaml").read_text()))
    audit = AuditLog(LOG_PATH, private)
    gateway = Gateway(policy, audit, FakeMCPServer())

    # An "operator" agent: may read, needs approval to delete.
    bot = new_agent("triage-bot", roles=["operator"])
    banner(f"Agent online: {bot}")

    banner("1) Allowed call — read a file")
    show(gateway.handle(bot, "read_file", path="notes.txt"))

    banner("2) Destructive call — delete a file (should be held for approval)")
    show(gateway.handle(bot, "delete_file", path="budget.csv"))

    banner("3) Disallowed call — a tool no role grants (default deny)")
    show(gateway.handle(bot, "exfiltrate_secrets", target="s3://attacker"))

    banner("Audit log written to .agentledger/audit.jsonl")
    result = verify_log(LOG_PATH, public)
    print(f"  verify: ok={result.ok}  events checked={result.checked}")

    banner("Now tamper with the log and re-verify (this is the point)")
    lines = LOG_PATH.read_text().splitlines()
    lines[0] = lines[0].replace('"read_file"', '"delete_file"')  # forge an event
    LOG_PATH.write_text("\n".join(lines) + "\n")
    tampered = verify_log(LOG_PATH, public)
    print(f"  verify after tamper: ok={tampered.ok}  ({tampered.error})")

    print("\n\033[1mSprint 1 done:\033[0m identity -> policy -> gateway -> "
          "tamper-evident audit, end to end.\n")


if __name__ == "__main__":
    main()
