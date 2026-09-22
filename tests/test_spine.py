"""Sprint 1 tests: the security guarantees, not just 'it runs'."""
from pathlib import Path

import yaml

from agents.identity import new_agent
from audit.keys import load_or_create_keypair
from audit.log import AuditLog, verify_log
from gateway.gateway import Gateway
from mcp_servers.fake_mcp import FakeMCPServer
from policy.engine import Decision, PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
RULES = yaml.safe_load((ROOT / "policy" / "policy.yaml").read_text())


def _stack(tmp_path):
    priv, pub = load_or_create_keypair(tmp_path / "k.pem")
    audit = AuditLog(tmp_path / "audit.jsonl", priv)
    gw = Gateway(PolicyEngine(RULES), audit, FakeMCPServer())
    return gw, pub, tmp_path / "audit.jsonl"


def test_default_deny(tmp_path):
    gw, _, _ = _stack(tmp_path)
    res = gw.handle(new_agent("a", ["reader"]), "delete_file", path="x")
    assert res.decision is Decision.DENY  # reader has no delete at all
    assert res.outcome == "blocked"
    assert res.result is None


def test_allow_executes(tmp_path):
    gw, _, _ = _stack(tmp_path)
    res = gw.handle(new_agent("a", ["reader"]), "read_file", path="notes.txt")
    assert res.decision is Decision.ALLOW
    assert res.outcome == "executed"
    assert "fake filesystem" in res.result


def test_destructive_needs_approval(tmp_path):
    gw, _, _ = _stack(tmp_path)
    res = gw.handle(new_agent("a", ["operator"]), "delete_file", path="budget.csv")
    assert res.decision is Decision.APPROVAL
    assert res.outcome == "pending_approval"
    assert res.result is None  # NOT executed


def test_unknown_role_is_denied(tmp_path):
    gw, _, _ = _stack(tmp_path)
    res = gw.handle(new_agent("a", ["intern"]), "read_file", path="notes.txt")
    assert res.decision is Decision.DENY


def test_audit_verifies_and_detects_tamper(tmp_path):
    gw, pub, log_path = _stack(tmp_path)
    agent = new_agent("a", ["operator"])
    gw.handle(agent, "read_file", path="notes.txt")
    gw.handle(agent, "delete_file", path="budget.csv")
    gw.handle(agent, "nope")

    assert verify_log(log_path, pub).ok is True

    lines = log_path.read_text().splitlines()
    lines[0] = lines[0].replace('"read_file"', '"delete_file"')
    log_path.write_text("\n".join(lines) + "\n")

    assert verify_log(log_path, pub).ok is False
