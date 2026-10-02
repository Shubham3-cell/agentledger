"""The Sentinel SOC tool is only reachable through the AgentLedger gateway.

Drives the simulated Sentinel server through the REAL gateway and asserts the four
gates on a SOC-triage workflow:
  - a read is ALLOWED under an "investigate" intent,
  - an injected device isolation is BLOCKED at the intent gate,
  - a read-only credential is BLOCKED at the scope gate,
  - a genuine isolation is HELD for human approval, then executes once approved.
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

POLICY = {
    "roles": {
        "soc-analyst": {
            "rules": [
                {"tool": "list_incidents", "effect": "allow"},
                {"tool": "get_incident", "effect": "allow"},
                {"tool": "get_incident_entities", "effect": "allow"},
                {"tool": "isolate_device", "effect": "approval"},  # consequential
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
    anchor = WormAnchor(tmp_path / "a.jsonl")
    audit = AuditLog(tmp_path / "audit.jsonl", priv, anchor=anchor)
    auth = AuthService()
    approvals = ApprovalService(reg, audit)
    gw = Gateway(auth, reg, PolicyEngine(POLICY), audit, approval=approvals)

    investigate = new_intent("investigate-incident", "read incident data only",
                             ["list_incidents", "get_incident", "get_incident_entities"])
    respond = new_intent("respond-incident", "contain a confirmed threat",
                         ["get_incident", "isolate_device"])
    return gw, auth, approvals, investigate, respond


def _token(auth, scopes):
    return auth.issue(new_agent("soc-agent", ["soc-analyst"]), scopes)


def test_read_incident_is_allowed(tmp_path):
    gw, auth, _, investigate, _ = _env(tmp_path)
    tok = _token(auth, ["sentinel:read", "sentinel:respond"])
    res = gw.handle(tok, "get_incident", intent=investigate, incident_id="INC-4471")
    assert res.decision is Decision.ALLOW
    assert res.result["title"] == "Password spray against finance users"


def test_injection_isolate_blocked_at_intent(tmp_path):
    gw, auth, _, investigate, _ = _env(tmp_path)
    tok = _token(auth, ["sentinel:read", "sentinel:respond"])
    # poisoned incident text tells the agent to isolate a device mid-investigation
    res = gw.handle(tok, "isolate_device", intent=investigate, device="FIN-LT-014")
    assert res.decision is Decision.DENY
    assert res.stage == "intent"


def test_readonly_token_blocked_at_scope(tmp_path):
    gw, auth, _, _, respond = _env(tmp_path)
    tok = _token(auth, ["sentinel:read"])  # no sentinel:respond
    res = gw.handle(tok, "isolate_device", intent=respond, device="FIN-LT-014")
    assert res.decision is Decision.DENY
    assert res.stage == "scope"


def test_isolate_held_for_approval_then_executes(tmp_path):
    gw, auth, approvals, _, respond = _env(tmp_path)
    tok = _token(auth, ["sentinel:read", "sentinel:respond"])
    res = gw.handle(tok, "isolate_device", intent=respond, device="FIN-LT-014")
    assert res.decision is Decision.APPROVAL
    assert res.outcome == "pending_approval"
    assert res.approval_id
    outcome = approvals.approve(res.approval_id, approver="analyst@lab")
    assert "isolated" in str(outcome.result).lower()
