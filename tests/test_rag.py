"""RAG: the retriever grounds triage in the right runbook."""
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
from policy.engine import PolicyEngine
from soc.retriever import RunbookRetriever
from soc.triage_agent import TriageAgent

POLICY = {"roles": {"soc-analyst": {"rules": [
    {"tool": "get_incident", "effect": "allow"},
    {"tool": "get_incident_entities", "effect": "allow"},
    {"tool": "isolate_device", "effect": "approval"},
]}}}


def test_retriever_picks_password_spray_runbook():
    rb = RunbookRetriever().retrieve("password spray detected T1110.003 against accounts", k=1)
    assert rb and rb[0].name == "password_spray"


def test_retriever_picks_legacy_auth_runbook():
    rb = RunbookRetriever().retrieve("legacy authentication sign-in T1078 IMAP", k=1)
    assert rb and rb[0].name == "legacy_auth"


def test_triage_report_is_grounded_in_a_runbook(tmp_path):
    sentinel = SentinelMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("get_incident", "Get an incident", "sentinel:read", sentinel))
    reg.register(ToolSpec("get_incident_entities", "Get entities", "sentinel:read", sentinel))
    reg.register(ToolSpec("isolate_device", "Isolate", "sentinel:respond", sentinel))
    priv, _ = load_or_create_keypair(tmp_path / "k.pem")
    audit = AuditLog(tmp_path / "audit.jsonl", priv, anchor=WormAnchor(tmp_path / "a.jsonl"))
    auth = AuthService()
    gw = Gateway(auth, reg, PolicyEngine(POLICY), audit, approval=ApprovalService(reg, audit))
    investigate = new_intent("investigate-incident", "read only",
                             ["get_incident", "get_incident_entities"])
    tok = auth.issue(new_agent("soc-agent", ["soc-analyst"]), ["sentinel:read", "sentinel:respond"])

    report = TriageAgent(gw, tok, investigate).triage("INC-4471")
    assert report.runbook is not None
    assert report.runbook["name"] == "password_spray"
    assert "Password Spray" in report.runbook["title"]
