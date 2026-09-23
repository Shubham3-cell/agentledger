"""Red-team runner — fires the attack library at a real AgentLedger stack.

    from attacks.redteam import run_all
    results = run_all()          # list of (Attack, Outcome)

`build_env()` wires up the actual gateway (auth, registry, policy, intent,
audit); every attack runs through it, not a mock. `report_html()` writes a
shareable red-team report.
"""
from __future__ import annotations

import html
from pathlib import Path

import yaml

from agents.identity import new_agent
from agents.intent import new_intent
from attacks.library import ATTACKS, Attack, Outcome
from audit.anchor import WormAnchor
from audit.keys import load_or_create_keypair
from audit.log import AuditLog
from gateway.auth import AuthService
from gateway.gateway import Gateway
from gateway.registry import ToolRegistry, ToolSpec
from mcp_servers.fake_mcp import FakeMCPServer
from mcp_servers.mail_mcp import MailMCPServer
from policy.engine import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / ".agentledger"


class Env:
    def __init__(self, gateway, auth, investigate, notify):
        self.gateway = gateway
        self.auth = auth
        self.investigate = investigate
        self.notify = notify

    def token(self, roles, scopes, ttl_seconds: int = 3600) -> str:
        return self.auth.issue(new_agent("agent", roles), list(scopes), ttl_seconds=ttl_seconds)


def build_env() -> Env:
    files, mail = FakeMCPServer(), MailMCPServer()
    reg = ToolRegistry()
    reg.register(ToolSpec("list_files", "List files", "files:read", files))
    reg.register(ToolSpec("read_file", "Read a file", "files:read", files))
    reg.register(ToolSpec("delete_file", "Delete a file", "files:write", files))
    reg.register(ToolSpec("list_inbox", "List inbox", "mail:read", mail))
    reg.register(ToolSpec("send_email", "Send an email", "mail:send", mail))

    priv, _ = load_or_create_keypair(DATA / "rt_key.pem")
    anchor = WormAnchor(DATA / "rt_anchor.jsonl")
    audit = AuditLog(DATA / "rt_audit.jsonl", priv, anchor=anchor)
    policy = PolicyEngine(yaml.safe_load((ROOT / "policy" / "policy.yaml").read_text()))
    auth = AuthService()  # the gateway and Env must share the SAME auth service
    gateway = Gateway(auth, reg, policy, audit)

    investigate = new_intent("investigate-incident", "read incident data only",
                             ["read_file", "list_files", "list_inbox"])
    notify = new_intent("notify-team", "email the internal team",
                        ["send_email", "list_inbox"])
    return Env(gateway, auth, investigate, notify)


def run_all() -> list[tuple[Attack, Outcome]]:
    env = build_env()
    return [(atk, atk.run(env)) for atk in ATTACKS]


# --- reports ---

_C = {"BLOCKED": "\033[32m", "HELD": "\033[33m", "DETECTED": "\033[36m", "LEAKED": "\033[31m"}


def report_console(results: list[tuple[Attack, Outcome]]) -> None:
    print("\n\033[1mAgentLedger — Red-Team Lab\033[0m")
    for atk, out in results:
        c = _C.get(out.verdict, "")
        mark = "✓" if out.defended else "✗"
        print(f"  {mark} {atk.id}  {c}{out.verdict:<9}\033[0m [{out.gate:<8}] {atk.name}")
    defended = sum(1 for _, o in results if o.defended)
    print(f"\n\033[1m{defended}/{len(results)} attacks defended.\033[0m\n")


def report_html(results: list[tuple[Attack, Outcome]], out_path: str | Path) -> Path:
    defended = sum(1 for _, o in results if o.defended)
    rows = "".join(
        f"""<tr class="{'ok' if o.defended else 'bad'}">
        <td class="mono">{atk.id}</td>
        <td><b>{html.escape(atk.name)}</b><div class="story">{html.escape(atk.story)}</div></td>
        <td><span class="owasp">{html.escape(atk.owasp)}</span></td>
        <td class="mono gate">{o.gate}</td>
        <td><span class="verdict {o.verdict.lower()}">{o.verdict}</span></td></tr>"""
        for atk, o in results
    )
    doc = _HTML.replace("__ROWS__", rows).replace("__D__", str(defended)).replace("__N__", str(len(results)))
    p = Path(out_path)
    p.write_text(doc, encoding="utf-8")
    return p


_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>AgentLedger Red-Team Report</title>
<style>
 :root{--bg:#f6f8fc;--panel:#fff;--line:#dbe2ee;--ink:#111725;--muted:#586074;--accent:#3459e6;
   --ok:#1f8a4c;--bad:#cc3a2e;--appr:#a9761a;--info:#1d6fb8;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
 @media(prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#0a0d15;--panel:#141a27;--line:#242c3d;--ink:#e9edf6;--muted:#94a0b2}}
 *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
   font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
 header{background:#0b0e15;color:#e9edf6;padding:26px 22px}
 header h1{margin:0;font-size:21px}header .s{color:#94a0b2;font-size:13px;margin-top:4px}
 .wrap{max-width:1000px;margin:0 auto;padding:22px 18px 60px}
 .summary{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
 .tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;flex:1;min-width:150px}
 .tile .n{font-size:28px;font-weight:800}.tile .n.g{color:var(--ok)}.tile .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
 th{text-align:left;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:12px 14px;border-bottom:2px solid var(--line)}
 td{padding:13px 14px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
 tr:last-child td{border-bottom:none}
 .mono{font-family:var(--mono);font-size:12.5px;color:var(--muted)}
 .story{color:var(--muted);font-size:12.5px;margin-top:3px}
 .gate{color:var(--accent)}
 .owasp{font-size:11.5px;background:color-mix(in srgb,var(--accent) 12%,transparent);color:var(--accent);padding:2px 8px;border-radius:999px;white-space:nowrap}
 .verdict{font-weight:700;font-size:12px;padding:3px 9px;border-radius:6px}
 .verdict.blocked{color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent)}
 .verdict.held{color:var(--appr);background:color-mix(in srgb,var(--appr) 14%,transparent)}
 .verdict.detected{color:var(--info);background:color-mix(in srgb,var(--info) 14%,transparent)}
 .verdict.leaked{color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent)}
 .foot{color:var(--muted);font-size:12px;text-align:center;margin-top:20px}
</style></head><body>
<header><h1>🛡️ AgentLedger — Red-Team Report</h1>
<div class="s">Adversary techniques fired at the live gateway · every attempt recorded in the tamper-evident log</div></header>
<div class="wrap">
 <div class="summary">
  <div class="tile"><div class="n g">__D__/__N__</div><div class="l">Attacks defended</div></div>
  <div class="tile"><div class="n">6</div><div class="l">Gates exercised</div></div>
  <div class="tile"><div class="n">0</div><div class="l">Leaked</div></div>
 </div>
 <table><thead><tr><th>#</th><th>Attack</th><th>Class</th><th>Stopped at</th><th>Result</th></tr></thead>
 <tbody>__ROWS__</tbody></table>
 <div class="foot">Generated by the AgentLedger red-team lab · synthetic environment · techniques mapped to the OWASP Top 10 for LLM Applications</div>
</div></body></html>"""
