"""AgentLedger — Sprint 2 end-to-end demo.

Run:  python demo.py

Sprint 1 proved the spine. Sprint 2 hardens the front door:
  1. Credentials are ISSUED with narrow scopes (least privilege).
  2. A valid, in-scope, policy-allowed call executes — routed via the registry.
  3. A destructive call is held for APPROVAL.
  4. A call OUTSIDE the credential's scope is blocked before policy even runs.
  5. An UNAUTHENTICATED token is rejected — and still audited.
  6. A REVOKED credential stops working instantly.
  7. The audit log verifies; tampering is caught.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from agents.identity import new_agent
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

    # Mint a credential: operator role, but scoped ONLY to files (no mail).
    bot = new_agent("triage-bot", roles=["operator"])
    token = auth.issue(bot, scopes=["files:read", "files:write"])
    banner(f"Issued credential for {bot}  scopes=[files:read, files:write]")

    banner("1) Valid, in-scope, allowed — read a file")
    show(gateway.handle(token, "read_file", path="notes.txt"))

    banner("2) Destructive but in-scope — delete (held for approval)")
    show(gateway.handle(token, "delete_file", path="budget.csv"))

    banner("3) Out of scope — send_email (credential has no mail:send)")
    show(gateway.handle(token, "send_email", to="x@y.com", subject="hi"))

    banner("4) Unauthenticated — a bogus token")
    show(gateway.handle("al_not_a_real_token", "read_file", path="notes.txt"))

    banner("5) Revoked — revoke the credential, then retry the read")
    auth.revoke(token)
    show(gateway.handle(token, "read_file", path="notes.txt"))

    banner("Audit log — every attempt above was recorded")
    result = verify_log(LOG_PATH, public)
    print(f"  verify: ok={result.ok}  events checked={result.checked}")

    banner("Tamper with the log and re-verify")
    lines = LOG_PATH.read_text().splitlines()
    lines[0] = lines[0].replace('"read_file"', '"delete_file"')
    LOG_PATH.write_text("\n".join(lines) + "\n")
    tampered = verify_log(LOG_PATH, public)
    print(f"  verify after tamper: ok={tampered.ok}  ({tampered.error})")

    print("\n\033[1mSprint 2 done:\033[0m authenticate -> registry -> scope -> "
          "policy -> execute -> tamper-evident audit.\n")


if __name__ == "__main__":
    main()
