"""Sprint 1-3 tests: the security guarantees, not just 'it runs'."""
from pathlib import Path

import yaml

from agents.identity import new_agent
from agents.intent import new_intent
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_log
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


def _registry():
    files, mail = FakeMCPServer(), MailMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("list_files", "List files", "files:read", files))
    reg.register(ToolSpec("read_file", "Read a file", "files:read", files))
    reg.register(ToolSpec("delete_file", "Delete a file", "files:write", files))
    reg.register(ToolSpec("list_inbox", "List inbox", "mail:read", mail))
    reg.register(ToolSpec("send_email", "Send an email", "mail:send", mail))
    return reg


def _stack(tmp_path):
    priv, pub = load_or_create_keypair(tmp_path / "k.pem")
    audit = AuditLog(tmp_path / "audit.jsonl", priv)
    auth = AuthService()
    gw = Gateway(auth, _registry(), PolicyEngine(RULES), audit)
    return gw, auth, pub, tmp_path / "audit.jsonl"


def _token(auth, scopes=None):
    return auth.issue(new_agent("a", ["operator"]), scopes or ALL_SCOPES)


# --- Sprint 1-2 guarantees still hold ---

def test_allow_executes_in_reports(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    res = gw.handle(_token(auth), "read_file", path=REPORT)
    assert res.decision is Decision.ALLOW and res.outcome == "executed"
    assert "revenue" in res.result


def test_unauthenticated_rejected_and_audited(tmp_path):
    gw, _, pub, log_path = _stack(tmp_path)
    res = gw.handle("al_bogus", "read_file", path=REPORT)
    assert res.decision is Decision.DENY and res.stage == "auth"
    assert res.event.agent_id == UNAUTHENTICATED
    assert verify_log(log_path, pub).ok is True


def test_out_of_scope_blocked(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read"])  # no mail:send
    res = gw.handle(token, "send_email", to="x@company.com", subject="hi")
    assert res.decision is Decision.DENY and res.stage == "scope"


# --- Sprint 3: per-parameter policy ---

def test_read_outside_reports_denied_by_argument(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    res = gw.handle(_token(auth), "read_file", path="/etc/passwd")
    assert res.decision is Decision.DENY and res.stage == "policy"
    assert "argument not permitted" in res.reason
    assert res.result is None  # the file exists, but policy refused


def test_send_external_denied_by_argument(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    res = gw.handle(_token(auth), "send_email", to="attacker@evil.com", subject="x")
    assert res.decision is Decision.DENY and res.stage == "policy"


def test_send_internal_needs_approval(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    res = gw.handle(_token(auth), "send_email", to="alex@company.com", subject="x")
    assert res.decision is Decision.APPROVAL and res.outcome == "pending_approval"


def test_delete_in_reports_needs_approval(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    res = gw.handle(_token(auth), "delete_file", path="/reports/old.txt")
    assert res.decision is Decision.APPROVAL


def test_missing_argument_fails_closed(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    res = gw.handle(_token(auth), "read_file")  # no path at all
    assert res.decision is Decision.DENY and res.stage == "policy"


# --- Sprint 3: intent scoping ---

def test_intent_blocks_out_of_task_tool(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    investigate = new_intent("investigate", "read only", ["read_file", "list_files"])
    res = gw.handle(_token(auth), "send_email", intent=investigate, to="alex@company.com", subject="x")
    assert res.decision is Decision.DENY and res.stage == "intent"


def test_intent_allows_in_task_tool(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    investigate = new_intent("investigate", "read only", ["read_file", "list_files"])
    res = gw.handle(_token(auth), "read_file", intent=investigate, path=REPORT)
    assert res.decision is Decision.ALLOW and res.outcome == "executed"


def test_intent_checked_before_policy(tmp_path):
    # even a call policy would ALLOW is stopped if the task's intent excludes it
    gw, auth, _, _ = _stack(tmp_path)
    only_mail = new_intent("notify", "send mail only", ["send_email"])
    res = gw.handle(_token(auth), "read_file", intent=only_mail, path=REPORT)
    assert res.decision is Decision.DENY and res.stage == "intent"


# --- audit still tamper-evident ---

def test_audit_detects_tamper(tmp_path):
    gw, auth, pub, log_path = _stack(tmp_path)
    token = _token(auth)
    gw.handle(token, "read_file", path=REPORT)
    gw.handle(token, "read_file", path="/etc/passwd")
    assert verify_log(log_path, pub).ok is True
    lines = log_path.read_text().splitlines()
    lines[0] = lines[0].replace("/reports/", "/etc/")
    log_path.write_text("\n".join(lines) + "\n")
    assert verify_log(log_path, pub).ok is False
