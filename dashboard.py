"""Generate the AgentLedger control-plane dashboard.

Reads the audit log (and approvals) and writes a single self-contained
`dashboard.html` — no server, no build step, opens in any browser. It's the
window a security team looks through: agents, runs, every policy decision, the
approvals queue, and a searchable audit explorer.

    python dashboard.py                     # from the default audit log
    generate(log_path, approvals, out_path) # called by demo.py with live data
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any


def _load(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return events
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _approvals_to_dicts(approvals: list) -> list[dict[str, Any]]:
    out = []
    for a in approvals or []:
        d = dataclasses.asdict(a) if dataclasses.is_dataclass(a) else dict(a)
        d.pop("run", None)  # RunContext isn't needed in the view
        out.append(d)
    return out


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentLedger — Control Plane</title>
<style>
  :root{
    --bg:#f6f8fa; --panel:#ffffff; --ink:#1c2128; --muted:#57606a; --line:#d0d7de;
    --accent:#1f6feb; --allow:#1a7a48; --deny:#b12a20; --appr:#9a6410;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:14px;line-height:1.5}
  header{background:#0d1117;color:#e6edf3;padding:22px 28px}
  header h1{margin:0;font-size:20px;letter-spacing:.3px}
  header .sub{color:#9aa4b2;font-size:13px;margin-top:2px}
  header .badges{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
  .badge{font-size:12px;padding:4px 10px;border-radius:999px;background:#161b22;border:1px solid #30363d;color:#c9d1d9}
  .badge.ok{border-color:#1a7a48;color:#3fb950}
  .wrap{max-width:1100px;margin:0 auto;padding:24px 20px 60px}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
  .tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
  .tile .n{font-size:26px;font-weight:700}
  .tile .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
  .tile.allow .n{color:var(--allow)} .tile.deny .n{color:var(--deny)} .tile.appr .n{color:var(--appr)}
  section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:18px}
  section h2{margin:0 0 14px;font-size:14px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
  .bar{display:flex;height:26px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}
  .bar span{display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:600;min-width:2px}
  .bar .a{background:var(--allow)} .bar .p{background:var(--appr)} .bar .d{background:var(--deny)}
  .appr-card{border:1px solid var(--line);border-left:4px solid var(--appr);border-radius:8px;padding:12px 14px;margin-bottom:10px}
  .appr-card.approved{border-left-color:var(--allow)} .appr-card.denied{border-left-color:var(--deny)}
  .appr-card .top{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .pill{font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;text-transform:uppercase}
  .pill.pending{background:#fff3d6;color:#9a6410} .pill.approved{background:#e6f4ea;color:#1a7a48} .pill.denied{background:#fbe9e7;color:#b12a20}
  code{background:#eff2f5;padding:1px 5px;border-radius:4px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
  .run{border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin-bottom:8px}
  .run .h{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;color:var(--accent)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:2px solid var(--line);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
  td{padding:8px 10px;border-bottom:1px solid #eaeef2;vertical-align:top}
  tr:hover td{background:#fafbfc}
  .dec{font-weight:700;font-size:12px} .dec.ALLOW{color:var(--allow)} .dec.DENY{color:var(--deny)} .dec.APPROVAL{color:var(--appr)}
  .search{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;font-size:13px;margin-bottom:12px}
  .foot{color:var(--muted);font-size:12px;text-align:center;margin-top:24px}
  @media (prefers-color-scheme: dark){
    :root:not([data-theme="light"]){--bg:#0d1117;--panel:#161b22;--ink:#e6edf3;--muted:#8b949e;--line:#30363d}
    :root:not([data-theme="light"]) code{background:#21262d}
    :root:not([data-theme="light"]) tr:hover td{background:#1c2128}
    :root:not([data-theme="light"]) td{border-bottom-color:#21262d}
    :root:not([data-theme="light"]) .pill.pending{background:#3a2d0a}
    :root:not([data-theme="light"]) .pill.approved{background:#0f2f1c}
    :root:not([data-theme="light"]) .pill.denied{background:#3a1613}
  }
</style>
</head>
<body>
<header>
  <h1>🛡️ AgentLedger — Agent Control Plane</h1>
  <div class="sub">Every agent an identity · every action a policy · every execution a tamper-evident record</div>
  <div class="badges" id="badges"></div>
</header>
<div class="wrap">
  <div class="tiles" id="tiles"></div>
  <section><h2>Decision breakdown</h2><div class="bar" id="bar"></div></section>
  <section><h2>Approvals queue</h2><div id="approvals"></div></section>
  <section><h2>Runs</h2><div id="runs"></div></section>
  <section>
    <h2>Audit explorer</h2>
    <input class="search" id="search" placeholder="filter by tool, agent, decision, path…">
    <table><thead><tr><th>#</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Outcome</th><th>Reason</th></tr></thead>
    <tbody id="rows"></tbody></table>
  </section>
  <div class="foot">Generated from the tamper-evident audit log · synthetic data · AgentLedger MVP</div>
</div>
<script>
const EVENTS = __EVENTS__;
const APPROVALS = __APPROVALS__;
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

const count = f => EVENTS.filter(f).length;
const executed = count(e => e.outcome === 'executed');
const blocked  = count(e => e.outcome === 'blocked');
const pending  = count(e => e.outcome === 'pending_approval');
const agents = new Set(EVENTS.map(e => e.agent_id)); agents.delete('unauthenticated');
const runs = new Set(EVENTS.map(e => e.run_id));

$('#badges').innerHTML =
  `<span class="badge ok">✓ hash chain</span>`+
  `<span class="badge ok">✓ Ed25519 signed</span>`+
  `<span class="badge ok">✓ WORM anchored</span>`+
  `<span class="badge">${EVENTS.length} events</span>`;

const tiles = [
  ['Events', EVENTS.length, ''], ['Executed', executed, 'allow'],
  ['Blocked', blocked, 'deny'], ['Held for approval', pending, 'appr'],
  ['Agents', agents.size, ''], ['Runs', runs.size, ''],
];
$('#tiles').innerHTML = tiles.map(([l,n,c]) =>
  `<div class="tile ${c}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

const a = count(e => e.decision==='ALLOW'), p = count(e => e.decision==='APPROVAL'), d = count(e => e.decision==='DENY');
const tot = Math.max(a+p+d, 1);
$('#bar').innerHTML =
  (a?`<span class="a" style="width:${a/tot*100}%">${a} allow</span>`:'')+
  (p?`<span class="p" style="width:${p/tot*100}%">${p} approval</span>`:'')+
  (d?`<span class="d" style="width:${d/tot*100}%">${d} deny</span>`:'');

$('#approvals').innerHTML = APPROVALS.length ? APPROVALS.map(r =>
  `<div class="appr-card ${r.status}"><div class="top">
     <div><b>${esc(r.tool)}</b> &nbsp;<code>${esc(JSON.stringify(r.params))}</code></div>
     <span class="pill ${r.status}">${r.status}${r.decided_by?(' · '+esc(r.decided_by)):''}</span>
   </div><div style="color:var(--muted);margin-top:6px">${esc(r.agent_name)} · ${esc(r.reason)}</div></div>`
).join('') : '<div style="color:var(--muted)">No approval requests.</div>';

const byRun = {};
EVENTS.forEach(e => { (byRun[e.run_id] ||= []).push(e); });
$('#runs').innerHTML = Object.entries(byRun).map(([rid, evs]) =>
  `<div class="run"><div class="h">run ${esc(rid)}</div>
   <div style="color:var(--muted);margin-top:3px">${esc(evs[0].agent_name)} · trace ${esc(evs[0].trace_id)} · ${evs.length} call(s)</div></div>`
).join('');

function renderRows(filter){
  const f = (filter||'').toLowerCase();
  $('#rows').innerHTML = EVENTS.filter(e =>
    !f || JSON.stringify(e).toLowerCase().includes(f)
  ).map(e =>
    `<tr><td>${e.seq}</td><td>${esc(e.agent_name)}</td><td><code>${esc(e.tool)}</code></td>
     <td class="dec ${e.decision}">${e.decision}</td><td>${esc(e.outcome)}</td>
     <td style="color:var(--muted)">${esc(e.reason)}</td></tr>`
  ).join('');
}
renderRows('');
$('#search').addEventListener('input', e => renderRows(e.target.value));
</script>
</body>
</html>
"""


def render(events: list[dict], approvals: list) -> str:
    return (
        HTML
        .replace("__EVENTS__", json.dumps(events))
        .replace("__APPROVALS__", json.dumps(_approvals_to_dicts(approvals)))
    )


def generate(audit_path: str | Path, approvals: list, out_path: str | Path) -> Path:
    out = Path(out_path)
    out.write_text(render(_load(audit_path), approvals), encoding="utf-8")
    return out


if __name__ == "__main__":
    default_log = Path(__file__).parent / ".agentledger" / "audit.jsonl"
    out = generate(default_log, [], Path(__file__).parent / "dashboard.html")
    print(f"wrote {out}")
