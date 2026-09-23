"""Sprint 1-4 tests: the security guarantees, not just 'it runs'."""
from pathlib import Path

import yaml

from agents.identity import new_agent
from agents.intent import new_intent
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


def _registry():
    files, mail = FakeMCPServer(), MailMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("list_files", "List files", "files:read", files))
    reg.register(ToolSpec("read_file", "Read a file", "files:read", files))
    reg.register(ToolSpec("delete_file", "Delete a file", "files:write", files))
    reg.register(ToolSpec("list_inbox", "List inbox", "mail:read", mail))
    reg.register(ToolSpec("send_email", "Send an email", "mail:send", mail))
    return reg


def _stack(tmp_path, with_anchor=False):
    priv, pub = load_or_create_keypair(tmp_path / "k.pem")
    anchor = WormAnchor(tmp_path / "anchor.jsonl") if with_anchor else None
    audit = AuditLog(tmp_path / "audit.jsonl", priv, anchor=anchor)
    auth = AuthService()
    gw = Gateway(auth, _registry(), PolicyEngine(RULES), audit)
    return gw, auth, pub, anchor, tmp_path / "audit.jsonl"


def _token(auth, scopes=None):
    return auth.issue(new_agent("a", ["operator"]), scopes or ALL_SCOPES)


# --- Sprint 1-3 guarantees still hold ---

def test_allow_executes_in_reports(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    res = gw.handle(_token(auth), "read_file", path=REPORT)
    assert res.decision is Decision.ALLOW and "revenue" in res.result


def test_read_outside_reports_denied_by_argument(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    res = gw.handle(_token(auth), "read_file", path="/etc/passwd")
    assert res.decision is Decision.DENY and res.stage == "policy"


def test_send_external_denied(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    res = gw.handle(_token(auth), "send_email", to="attacker@evil.com", subject="x")
    assert res.decision is Decision.DENY and res.stage == "policy"


def test_intent_blocks_out_of_task_tool(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    investigate = new_intent("investigate", "read only", ["read_file"])
    res = gw.handle(_token(auth), "send_email", intent=investigate, to="a@company.com", subject="x")
    assert res.decision is Decision.DENY and res.stage == "intent"


def test_unauthenticated_rejected_and_audited(tmp_path):
    gw, _, pub, _, log_path = _stack(tmp_path)
    res = gw.handle("al_bogus", "read_file", path=REPORT)
    assert res.decision is Decision.DENY and res.event.agent_id == UNAUTHENTICATED
    assert verify_log(log_path, pub).ok is True


# --- Sprint 4: trace hierarchy ---

def test_run_context_threads_trace(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    token = _token(auth)
    agent = new_agent("a", ["operator"])
    run = new_run(agent.agent_id)
    e1 = gw.handle(token, "list_files", run=run).event
    e2 = gw.handle(token, "read_file", run=run, path=REPORT).event
    assert e1.trace_id == e2.trace_id == run.trace_id
    assert e1.run_id == e2.run_id == run.run_id
    assert e1.seq != e2.seq  # distinct events, same trace


def test_events_without_run_get_distinct_traces(tmp_path):
    gw, auth, *_ = _stack(tmp_path)
    token = _token(auth)
    e1 = gw.handle(token, "list_files").event
    e2 = gw.handle(token, "list_files").event
    assert e1.trace_id != e2.trace_id


# --- Sprint 4: WORM anchor + truncation ---

def test_evidence_verifies_with_anchor(tmp_path):
    gw, auth, pub, anchor, log_path = _stack(tmp_path, with_anchor=True)
    token = _token(auth)
    gw.handle(token, "list_files")
    gw.handle(token, "read_file", path=REPORT)
    assert verify_evidence(log_path, pub, anchor).ok is True


def test_anchor_detects_truncation(tmp_path):
    gw, auth, pub, anchor, log_path = _stack(tmp_path, with_anchor=True)
    token = _token(auth)
    gw.handle(token, "list_files")
    gw.handle(token, "read_file", path=REPORT)
    gw.handle(token, "read_file", path="/etc/passwd")

    # Truncate the tail: delete the last event.
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join(lines[:-1]) + "\n")

    # The internal chain alone accepts it (it's still consistent)...
    assert verify_log(log_path, pub).ok is True
    # ...but the external anchor catches the truncation.
    res = verify_evidence(log_path, pub, anchor)
    assert res.ok is False and "truncated" in res.error


def test_midchain_edit_still_caught(tmp_path):
    gw, auth, pub, anchor, log_path = _stack(tmp_path, with_anchor=True)
    token = _token(auth)
    gw.handle(token, "list_files")
    gw.handle(token, "read_file", path=REPORT)
    lines = log_path.read_text().splitlines()
    lines[0] = lines[0].replace("list_files", "delete_file")
    log_path.write_text("\n".join(lines) + "\n")
    assert verify_evidence(log_path, pub, anchor).ok is False
