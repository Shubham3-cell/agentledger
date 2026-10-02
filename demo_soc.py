"""AgentLedger — end-to-end AI SOC triage demo.

Runs one incident through the whole stack on SIMULATED data (no Azure, no keys):
an AI agent investigates an incident THROUGH the gateway, grounds its triage in a
runbook (RAG), and recommends containment — then is shown it cannot act alone. The
isolation is blocked under the investigate intent, held for human approval under
the respond intent, and only executes once a human approves. Every step is written
to the tamper-evident audit log.

    python demo_soc.py
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from agents.identity import new_agent
from agents.intent import new_intent
from approvals.store import ApprovalService
from audit.anchor import WormAnchor
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_evidence
from gateway.auth import AuthService
from gateway.gateway import Gateway
from gateway.registry import ToolRegistry, ToolSpec
from mcp_servers.sentinel_mcp import SentinelMCPServer
from policy.engine import PolicyEngine
from soc.triage_agent import TriageAgent

G, Y, C, R, B, X = "\033[32m", "\033[33m", "\033[36m", "\033[31m", "\033[1m", "\033[0m"

POLICY = {"roles": {"soc-analyst": {"rules": [
    {"tool": "list_incidents", "effect": "allow"},
    {"tool": "get_incident", "effect": "allow"},
    {"tool": "get_incident_entities", "effect": "allow"},
    {"tool": "isolate_device", "effect": "approval"},
]}}}


def build(data: Path):
    sentinel = SentinelMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("list_incidents", "List incidents", "sentinel:read", sentinel))
    reg.register(ToolSpec("get_incident", "Get incident", "sentinel:read", sentinel))
    reg.register(ToolSpec("get_incident_entities", "Get entities", "sentinel:read", sentinel))
    reg.register(ToolSpec("isolate_device", "Isolate device", "sentinel:respond", sentinel))
    priv, pub = load_or_create_keypair(data / "k.pem")
    anchor = WormAnchor(data / "a.jsonl")
    audit = AuditLog(data / "audit.jsonl", priv, anchor=anchor)
    auth = AuthService()
    approvals = ApprovalService(reg, audit)
    gw = Gateway(auth, reg, PolicyEngine(POLICY), audit, approval=approvals)
    investigate = new_intent("investigate-incident", "read incident data only",
                             ["list_incidents", "get_incident", "get_incident_entities"])
    respond = new_intent("respond-incident", "contain a confirmed threat",
                         ["get_incident", "isolate_device"])
    return sentinel, gw, auth, approvals, audit, pub, anchor, investigate, respond


def main():
    data = Path(tempfile.mkdtemp(prefix="socdemo_"))
    sentinel, gw, auth, approvals, audit, pub, anchor, investigate, respond = build(data)
    token = auth.issue(new_agent("soc-agent", ["soc-analyst"]), ["sentinel:read", "sentinel:respond"])

    print(f"{B}=== AgentLedger — AI SOC triage (simulated incident, no cloud, no keys) ==={X}\n")

    print(f"{B}1 · The AI agent investigates incident INC-4471 — through the gateway{X}")
    report = TriageAgent(gw, token, investigate).triage("INC-4471")
    print(f"   Incident : {report.title}  [{report.severity}]")
    print(f"   Summary  : {report.summary}")
    for f in report.findings:
        print(f"   - {f}")
    if report.runbook:
        print(f"   {C}Runbook  : {report.runbook['title']}  (retrieved via RAG){X}")
    ra = report.recommended_action
    print(f"   {Y}Recommends: {ra['action']} -> {ra.get('target')}  ({ra['rationale']}){X}")
    print(f"   requires_human_approval = {report.requires_human_approval}\n")

    print(f"{B}2 · The agent cannot act on its own{X}")
    res = gw.handle(token, "isolate_device", intent=investigate, device=ra.get("target"))
    print(f"   agent tries to isolate under its investigate intent -> "
          f"{R}{res.decision.value} at {res.stage} gate{X}\n")

    print(f"{B}3 · Escalated to response — held for a human{X}")
    res = gw.handle(token, "isolate_device", intent=respond, device=ra.get("target"))
    print(f"   proposed under respond intent -> {Y}{res.outcome}  ({res.approval_id}){X}")
    outcome = approvals.approve(res.approval_id, approver="analyst@soc")
    print(f"   {G}human approves -> {outcome.result}{X}\n")

    v = verify_evidence(audit.path, pub, anchor)
    print(f"{B}4 · Evidence{X}  every step signed & recorded -> "
          f"verify_evidence ok={G if v.ok else R}{v.ok}{X}, events={v.checked}")
    print(f"\n{B}The AI investigated and recommended — a human authorised. "
          f"Nothing left the environment.{X}")

    shutil.rmtree(data, ignore_errors=True)


if __name__ == "__main__":
    main()
