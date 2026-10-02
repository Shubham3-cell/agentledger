"""The SOC agent investigates through the gateway and can never act autonomously.

Proves the core governance property: the agent reads evidence and recommends an
action, but a consequential action is blocked under an investigate intent and only
executes after human approval under a respond intent.
"""
from agents.identity import new_agent
from agents.intent import new_intent
from approvals.store import ApprovalService
from audit.anchor import WormAnchor
from audit.keys import load_or_create_keypair
from audit.log import AuditLog
from gateway.auth import AuthService
from gateway.gateway import Gateway
from gateway.registry import ToolRegistry, ToolSpec
from mcp_servers.sentinel_mcp import SentinelMCPServer
from policy.engine import Decision, PolicyEngine
from soc.triage_agent import TriageAgent

POLICY = {
    "roles": {
        "soc-analyst": {
            "rules": [
                {"tool": "list_incidents", "effect": "allow"},
                {"tool": "get_incident", "effect": "allow"},
                {"tool": "get_incident_entities", "effect": "allow"},
                {"tool": "isolate_device", "effect": "approval"},
            ]
        }
    }
}


def _env(tmp_path):
    sentinel = SentinelMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("list_incidents", "List incidents", "sentinel:read", sentinel))
    reg.register(ToolSpec("get_incident", "Get an incident", "sentinel:read", sentinel))
    reg.register(ToolSpec("get_incident_entities", "Get entities", "sentinel:read", sentinel))
    reg.register(ToolSpec("isolate_device", "Isolate a device", "sentinel:respond", sentinel))
    priv, _ = load_or_create_keypair(tmp_path / "k.pem")
    audit = AuditLog(tmp_path / "audit.jsonl", priv, anchor=WormAnchor(tmp_path / "a.jsonl"))
    auth = AuthService()
    approvals = ApprovalService(reg, audit)
    gw = Gateway(auth, reg, PolicyEngine(POLICY), audit, approval=approvals)
    investigate = new_intent("investigate-incident", "read incident data only",
                             ["list_incidents", "get_incident", "get_incident_entities"])
    respond = new_intent("respond-incident", "contain a confirmed threat",
                         ["get_incident", "isolate_device"])
    return gw, auth, approvals, sentinel, investigate, respond


def _token(auth, scopes):
    return auth.issue(new_agent("soc-agent", ["soc-analyst"]), scopes)


def test_triage_recommends_isolation_for_high_incident(tmp_path):
    gw, auth, _, sentinel, investigate, _ = _env(tmp_path)
    agent = TriageAgent(gw, _token(auth, ["sentinel:read", "sentinel:respond"]), investigate)
    report = agent.triage("INC-4471")
    assert report.title == "Password spray against finance users"
    assert report.severity == "High"
    assert report.recommended_action["action"] == "isolate_device"
    assert report.recommended_action["target"] == "FIN-LT-014"
    assert report.requires_human_approval is True
    # the agent only READ — it never isolated anything itself
    assert sentinel._isolated == []


def test_agent_cannot_act_autonomously_under_investigate(tmp_path):
    gw, auth, _, _, investigate, _ = _env(tmp_path)
    tok = _token(auth, ["sentinel:read", "sentinel:respond"])
    # even if the agent tried to execute its own recommendation under investigate:
    res = gw.handle(tok, "isolate_device", intent=investigate, device="FIN-LT-014")
    assert res.decision is Decision.DENY and res.stage == "intent"


def test_recommendation_executes_only_via_human_approval(tmp_path):
    gw, auth, approvals, sentinel, _, respond = _env(tmp_path)
    tok = _token(auth, ["sentinel:read", "sentinel:respond"])
    res = gw.handle(tok, "isolate_device", intent=respond, device="FIN-LT-014")
    assert res.decision is Decision.APPROVAL
    approvals.approve(res.approval_id, approver="analyst@lab")
    assert "FIN-LT-014" in sentinel._isolated


def test_medium_incident_recommends_monitor(tmp_path):
    gw, auth, _, _, investigate, _ = _env(tmp_path)
    agent = TriageAgent(gw, _token(auth, ["sentinel:read"]), investigate)
    report = agent.triage("INC-4472")
    assert report.severity == "Medium"
    assert report.recommended_action["action"] == "monitor"
    assert report.requires_human_approval is False
