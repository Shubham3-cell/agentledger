"""Sprint 1-5 tests: the security guarantees, not just 'it runs'."""
from pathlib import Path

import yaml

import dashboard
from agents.identity import new_agent
from agents.intent import new_intent
from approvals.store import ApprovalService
from audit.anchor import WormAnchor
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_evidence, verify_log
from audit.trace import new_run
from gateway.auth import AuthService
from gateway.gateway import Gateway, UNAUTHENTICATED
from gateway.registry import ToolRegistry, ToolSpec
from mcp_servers.fake_mcp import FakeMCPServer
from mcp_servers.mail_mcp import MailMCPServer
from policy.engine import Decision, PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
RULES = yaml.safe_load((ROOT / "policy" / "policy.yaml").read_text())
REPORT = "/reports/q3-summary.txt"
ALL_SCOPES = ["files:read", "files:write", "mail:read", "mail:send"]


def _stack(tmp_path, with_anchor=False):
    files, mail = FakeMCPServer(), MailMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("list_files", "List files", "files:read", files))
    reg.register(ToolSpec("read_file", "Read a file", "files:read", files))
    reg.register(ToolSpec("delete_file", "Delete a file", "files:write", files))
    reg.register(ToolSpec("list_inbox", "List inbox", "mail:read", mail))
    reg.register(ToolSpec("send_email", "Send an email", "mail:send", mail))
    priv, pub = load_or_create_keypair(tmp_path / "k.pem")
    anchor = WormAnchor(tmp_path / "anchor.jsonl") if with_anchor else None
    audit = AuditLog(tmp_path / "audit.jsonl", priv, anchor=anchor)
    auth = AuthService()
    approvals = ApprovalService(reg, audit)
    gw = Gateway(auth, reg, PolicyEngine(RULES), audit, approval=approvals)
    return gw, auth, pub, anchor, approvals, mail, tmp_path / "audit.jsonl"


def _token(auth, scopes=None):
    return auth.issue(new_agent("a", ["operator"]), scopes or ALL_SCOPES)


# --- earlier-sprint guarantees still hold ---

def test_allow_executes(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    assert gw.handle(_token(auth), "read_file", path=REPORT).outcome == "executed"


def test_argument_denied(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    r = gw.handle(_token(auth), "read_file", path="/etc/passwd")
    assert r.decision is Decision.DENY and r.stage == "policy"


def test_intent_blocks(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    only_read = new_intent("read", "read only", ["read_file"])
    r = gw.handle(_token(auth), "send_email", intent=only_read, to="a@company.com", subject="x")
    assert r.decision is Decision.DENY and r.stage == "intent"


def test_unauthenticated(tmp_path):
    gw, _, pub, _, _, _, log = _stack(tmp_path)
    r = gw.handle("bogus", "read_file", path=REPORT)
    assert r.decision is Decision.DENY and r.event.agent_id == UNAUTHENTICATED
    assert verify_log(log, pub).ok is True


# --- Sprint 5: human-in-the-loop approval ---

def test_consequential_action_is_held_not_executed(tmp_path):
    gw, auth, _, _, approvals, mail, _ = _stack(tmp_path)
    r = gw.handle(_token(auth), "send_email", to="alex@company.com", subject="x")
    assert r.decision is Decision.APPROVAL and r.outcome == "pending_approval"
    assert r.approval_id is not None
    assert len(approvals.pending()) == 1
    assert mail._sent == []  # NOT sent yet


def test_approve_executes_and_audits(tmp_path):
    gw, auth, pub, _, approvals, mail, log = _stack(tmp_path)
    r = gw.handle(_token(auth), "send_email", to="alex@company.com", subject="x")
    out = approvals.approve(r.approval_id, "lead@company.com")
    assert out.request.status == "approved" and out.request.decided_by == "lead@company.com"
    assert mail._sent == [{"to": "alex@company.com", "subject": "x"}]  # NOW sent
    assert out.event.outcome == "executed" and "approved by lead@company.com" in out.event.reason
    assert not approvals.pending()


def test_deny_blocks_and_audits(tmp_path):
    gw, auth, _, _, approvals, mail, _ = _stack(tmp_path)
    r = gw.handle(_token(auth), "delete_file", path="/reports/old.txt")
    out = approvals.deny(r.approval_id, "lead@company.com")
    assert out.request.status == "denied"
    assert out.event.outcome == "blocked" and "denied by lead@company.com" in out.event.reason


def test_cannot_decide_twice(tmp_path):
    gw, auth, _, _, approvals, _, _ = _stack(tmp_path)
    r = gw.handle(_token(auth), "send_email", to="alex@company.com", subject="x")
    approvals.approve(r.approval_id, "lead@company.com")
    try:
        approvals.approve(r.approval_id, "someone-else")
        assert False, "double-decide should raise"
    except ValueError:
        pass


def test_evidence_holds_through_approval(tmp_path):
    gw, auth, pub, anchor, approvals, _, log = _stack(tmp_path, with_anchor=True)
    r = gw.handle(_token(auth), "send_email", to="alex@company.com", subject="x")
    approvals.approve(r.approval_id, "lead@company.com")
    assert verify_evidence(log, pub, anchor).ok is True


# --- Sprint 5: dashboard ---

def test_dashboard_renders_from_events(tmp_path):
    gw, auth, _, _, approvals, _, log = _stack(tmp_path)
    r = gw.handle(_token(auth), "send_email", to="alex@company.com", subject="x")
    approvals.approve(r.approval_id, "lead@company.com")
    html = dashboard.generate(log, approvals.all(), tmp_path / "d.html").read_text()
    assert "AgentLedger" in html and "Audit explorer" in html
    assert "send_email" in html and "lead@company.com" in html
