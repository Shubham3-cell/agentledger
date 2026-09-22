"""Sprint 1 + 2 tests: the security guarantees, not just 'it runs'."""
from pathlib import Path

import yaml

from agents.identity import new_agent
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


def test_allow_executes(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read"])
    res = gw.handle(token, "read_file", path="notes.txt")
    assert res.decision is Decision.ALLOW and res.outcome == "executed"
    assert "fake filesystem" in res.result


def test_destructive_needs_approval(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read", "files:write"])
    res = gw.handle(token, "delete_file", path="budget.csv")
    assert res.decision is Decision.APPROVAL and res.outcome == "pending_approval"
    assert res.result is None


def test_out_of_scope_blocked_before_policy(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read"])
    res = gw.handle(token, "send_email", to="x@y.com", subject="hi")
    assert res.decision is Decision.DENY and res.stage == "scope"
    assert res.result is None


def test_unauthenticated_rejected_and_audited(tmp_path):
    gw, _, pub, log_path = _stack(tmp_path)
    res = gw.handle("al_bogus", "read_file", path="notes.txt")
    assert res.decision is Decision.DENY and res.stage == "auth"
    assert res.event.agent_id == UNAUTHENTICATED
    assert verify_log(log_path, pub).ok is True  # the rejection was still recorded


def test_missing_token_rejected(tmp_path):
    gw, _, _, _ = _stack(tmp_path)
    res = gw.handle(None, "read_file", path="notes.txt")
    assert res.decision is Decision.DENY and res.stage == "auth"


def test_revocation_takes_effect(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    agent = new_agent("a", ["operator"])
    token = auth.issue(agent, ["files:read"])
    assert gw.handle(token, "read_file", path="notes.txt").outcome == "executed"
    auth.revoke(token)
    res = gw.handle(token, "read_file", path="notes.txt")
    assert res.decision is Decision.DENY and res.stage == "auth"


def test_unknown_tool_blocked(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read"])
    res = gw.handle(token, "rm_minus_rf", path="/")
    assert res.decision is Decision.DENY and res.stage == "registry"


def test_expired_credential_rejected(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read"], ttl_seconds=-1)
    res = gw.handle(token, "read_file", path="notes.txt")
    assert res.decision is Decision.DENY and res.stage == "auth"


def test_registry_routes_across_servers(tmp_path):
    gw, auth, _, _ = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read", "mail:read"])
    inbox = gw.handle(token, "list_inbox")  # routed to the MAIL server
    assert inbox.outcome == "blocked" or inbox.outcome == "executed"
    # list_inbox isn't in policy for 'operator', so policy denies — but it
    # authenticated and passed scope, proving the registry resolved a mail tool.
    assert inbox.stage in ("policy", "execute")


def test_audit_detects_tamper(tmp_path):
    gw, auth, pub, log_path = _stack(tmp_path)
    token = auth.issue(new_agent("a", ["operator"]), ["files:read", "files:write"])
    gw.handle(token, "read_file", path="notes.txt")
    gw.handle(token, "delete_file", path="budget.csv")
    assert verify_log(log_path, pub).ok is True

    lines = log_path.read_text().splitlines()
    lines[0] = lines[0].replace('"read_file"', '"delete_file"')
    log_path.write_text("\n".join(lines) + "\n")
    assert verify_log(log_path, pub).ok is False
