"""AgentLedger — REAL Entra lab (Sprint 7).

Runs the real gateway with a REAL Microsoft Graph MCP tool: the ALLOW step makes
an actual Graph call to *your* tenant, while a prompt-injection attempt to
disable a user is stopped at the intent gate. Same four gates, real identity.

Setup (see the lab instructions):
    pip install msal requests
    create lab_secrets.py  (copy lab_secrets.example, paste your client secret)
    python practice_entra.py
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

# --- load local credentials (never committed) ---
try:
    import lab_secrets  # your local file (gitignored)
    os.environ.setdefault("AL_TENANT_ID", lab_secrets.TENANT_ID)
    os.environ.setdefault("AL_CLIENT_ID", lab_secrets.CLIENT_ID)
    os.environ.setdefault("AL_CLIENT_SECRET", lab_secrets.CLIENT_SECRET)
except ImportError:
    pass  # or rely on env vars already set

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
from mcp_servers.graph_mcp import GraphMCPServer
from policy.engine import PolicyEngine

# a SOC analyst policy for the real Entra tools
POLICY = {
    "roles": {
        "soc-analyst": {
            "rules": [
                {"tool": "list_users", "effect": "allow"},
                {"tool": "read_signins", "effect": "allow"},
                {"tool": "disable_user", "effect": "approval"},  # never silent
            ]
        }
    }
}

G, Y, C, R, B, X = "\033[32m", "\033[33m", "\033[36m", "\033[31m", "\033[1m", "\033[0m"
MARK = {"executed": f"{G}✓ EXECUTED{X}", "blocked": f"{R}✗ BLOCKED{X}",
        "pending_approval": f"{Y}⏸ HELD FOR HUMAN{X}"}


def show(step, story, res, expect):
    print(f"\n{B}{step}{X}  {story}")
    print(f"     gate: {C}{res.stage:<9}{X}  ->  {MARK[res.outcome]}")
    print(f"     why : {res.reason}")
    if res.result is not None:
        print(f"     data: {res.result}")
    print(f"     (expected: {expect})")


def safe_handle(gw, *args, **kwargs):
    """Wrap a gateway call so a live Graph error doesn't crash the whole lab."""
    try:
        return gw.handle(*args, **kwargs), None
    except Exception as exc:  # network / license / permission issue on execute
        return None, exc


def main():
    data = Path(tempfile.mkdtemp(prefix="entra_lab_"))
    graph = GraphMCPServer()  # authenticates to YOUR tenant on first call

    reg = ToolRegistry()
    reg.register(ToolSpec("list_users", "List users", "entra:read", graph))
    reg.register(ToolSpec("read_signins", "Read sign-in logs", "entra:read", graph))
    reg.register(ToolSpec("disable_user", "Disable a user", "entra:write", graph))

    priv, pub = load_or_create_keypair(data / "key.pem")
    anchor = WormAnchor(data / "anchor.jsonl")
    audit = AuditLog(data / "audit.jsonl", priv, anchor=anchor)
    auth = AuthService()
    approvals = ApprovalService(reg, audit)
    gw = Gateway(auth, reg, PolicyEngine(POLICY), audit, approval=approvals)

    print(f"{B}=== REAL Entra lab — SOC agent through the AgentLedger gateway ==={X}")
    print(f"tenant: {os.environ.get('AL_TENANT_ID')}")

    soc = new_agent("entra-soc-agent", ["soc-analyst"])
    soc_token = auth.issue(soc, ["entra:read", "entra:write"])
    ro = new_agent("readonly-agent", ["soc-analyst"])
    ro_token = auth.issue(ro, ["entra:read"])  # no entra:write

    investigate = new_intent("investigate-identity", "read directory + sign-ins",
                             ["list_users", "read_signins"])
    remediate = new_intent("remediate-identity", "contain a compromised account",
                           ["read_signins", "disable_user"])
    print(f"  investigate-identity -> {sorted(investigate.allowed_tools)}")

    run = new_run(soc.agent_id)

    # 1. AUTH — forged token
    r, _ = safe_handle(gw, "al_forged-token", "list_users", intent=investigate, run=run)
    show("1 · AUTHENTICATE", "attacker replays a forged token", r, "blocked at auth")

    # 2. SCOPE — read-only credential tries a write action
    r, _ = safe_handle(gw, ro_token, "disable_user", intent=remediate,
                       run=new_run(ro.agent_id), userPrincipalName="someone@x.com")
    show("2 · SCOPE", "read-only agent tries to disable a user (entra:write not granted)",
         r, "blocked at scope")

    # 3. INTENT — the injection: disable a user during an investigation
    r, _ = safe_handle(gw, soc_token, "disable_user", intent=investigate, run=run,
                       userPrincipalName="ceo@yourtenant.com")
    show("3 · INTENT", "poisoned data says 'disable this account now'", r,
         "blocked at intent (disable_user not in investigate)")

    # 4. ALLOW — a REAL Graph call to your tenant
    r, err = safe_handle(gw, soc_token, "list_users", intent=investigate, run=run)
    if err:
        print(f"\n{B}4 · ALLOW{X}  read real users from your tenant")
        print(f"     {R}graph call failed:{X} {err}")
    else:
        show("4 · ALLOW", "the real task: list users from YOUR Entra tenant", r,
             "executed — real data")

    # 4b. bonus: real sign-in logs (needs Entra ID P1 on the tenant)
    r, err = safe_handle(gw, soc_token, "read_signins", intent=investigate, run=run, top=3)
    if err:
        print(f"\n{B}4b · read_signins{X}  (optional — needs Entra ID P1)")
        print(f"     {Y}skipped:{X} {err}")
    elif r is not None:
        show("4b · ALLOW", "read recent sign-ins from YOUR tenant", r, "executed — real data")

    # 5. APPROVAL — destructive action held for a human (dry-run, disables no one)
    r, _ = safe_handle(gw, soc_token, "disable_user", intent=remediate, run=run,
                       userPrincipalName="test@yourtenant.com")
    show("5 · APPROVAL", "remediation wants to disable an account", r,
         "held for a human")
    if r and r.approval_id:
        outcome = approvals.approve(r.approval_id, approver="analyst@lab")
        print(f"     {G}human decision:{X} approved {r.approval_id} -> {outcome.result}")

    # 6. EVIDENCE
    v = verify_evidence(audit.path, pub, anchor)
    print(f"\n{B}6 · EVIDENCE{X}  every attempt signed & recorded")
    print(f"     verify_evidence -> ok={G if v.ok else R}{v.ok}{X}, events={v.checked}")

    print(f"\n{B}=== Tamper-evident audit trail ==={X}")
    import json
    for line in Path(audit.path).read_text().splitlines():
        if line.strip():
            ev = json.loads(line)
            d = ev["decision"]
            col = G if d == "ALLOW" else (Y if d == "APPROVAL" else R)
            print(f"  seq {ev['seq']:>2}  {col}{d:<9}{X} {ev['tool']:<13} {ev['reason']}")

    shutil.rmtree(data, ignore_errors=True)
    print(f"\n{B}Real Entra identity, four gates, injection stopped, every call logged.{X}")


if __name__ == "__main__":
    main()
