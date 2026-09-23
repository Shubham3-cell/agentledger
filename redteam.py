"""AgentLedger — Red-Team Lab entry point.

Run:  python redteam.py   (then open redteam-report.html)

Fires the full attack library at the live gateway, prints the result, and writes
a shareable red-team report.
"""
from pathlib import Path

from attacks.redteam import report_console, report_html, run_all

if __name__ == "__main__":
    results = run_all()
    report_console(results)
    out = report_html(results, Path(__file__).parent / "redteam-report.html")
    print(f"Report written -> {out.name}  (open it in a browser)")
