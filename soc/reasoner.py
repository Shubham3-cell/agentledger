"""Triage reasoners — how the SOC agent turns incident evidence into a recommendation.

RuleBasedReasoner (default) is deterministic: no LLM, no API key, no cost — so the
agent is fully testable in CI and explainable in an interview. A Claude-backed
reasoner can be dropped in by implementing the same `assess()` method; see
ClaudeReasoner, which is OPTIONAL, needs ANTHROPIC_API_KEY, and is never exercised
by the test suite. Swapping the reasoner changes the brain; the gateway, approval
and audit governance around the agent stay exactly the same.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Assessment:
    summary: str
    risk: str                 # low | medium | high
    recommended_action: dict  # {"action": ..., "target": ..., "rationale": ...}


class Reasoner(Protocol):
    def assess(self, incident: dict, entities: dict) -> Assessment: ...


class RuleBasedReasoner:
    """Deterministic triage logic — explainable, free, and CI-safe."""

    def assess(self, incident: dict, entities: dict) -> Assessment:
        severity = str(incident.get("severity", "")).lower()
        devices = entities.get("devices") or []
        accounts = entities.get("accounts") or []
        alerts = ", ".join(incident.get("alerts", [])) or "no alerts"
        summary = (
            f"{incident.get('title')} — severity {incident.get('severity')}; "
            f"{len(accounts)} account(s), {len(devices)} device(s); {alerts}."
        )

        if severity == "high" and devices:
            return Assessment(
                summary=summary, risk="high",
                recommended_action={
                    "action": "isolate_device",
                    "target": devices[0],
                    "rationale": "High-severity incident touching an endpoint — contain it.",
                },
            )
        if severity == "high" and accounts:
            return Assessment(
                summary=summary, risk="high",
                recommended_action={
                    "action": "reset_credentials",
                    "target": accounts[0],
                    "rationale": "High-severity account compromise — force a credential reset.",
                },
            )
        return Assessment(
            summary=summary, risk=severity or "low",
            recommended_action={
                "action": "monitor",
                "target": None,
                "rationale": "No containment warranted yet — continue monitoring.",
            },
        )


class ClaudeReasoner:
    """OPTIONAL Claude-backed reasoner. Not used in CI. Needs ANTHROPIC_API_KEY.

    Deliberately small, to show the seam: the LLM only *recommends*; the gateway
    and a human still decide. Enable it by installing `anthropic`, setting the key,
    and passing ClaudeReasoner() to TriageAgent.
    """

    def __init__(self, model: str = "claude-3-5-sonnet-latest") -> None:
        self.model = model

    def assess(self, incident: dict, entities: dict) -> Assessment:  # pragma: no cover
        import os

        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ClaudeReasoner needs ANTHROPIC_API_KEY (optional component).")
        import anthropic  # optional dependency, not required for the default agent

        client = anthropic.Anthropic()
        prompt = (
            "You are a SOC analyst. Triage this incident and recommend exactly ONE "
            "action from {isolate_device, reset_credentials, monitor}. "
            f"Incident: {incident}. Entities: {entities}. "
            "Reply strictly as: risk|action|target|rationale"
        )
        msg = client.messages.create(
            model=self.model, max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        parts = (msg.content[0].text.split("|") + ["", "", "", ""])[:4]
        risk, action, target, rationale = (p.strip() for p in parts)
        return Assessment(
            summary=f"[claude] {incident.get('title')}",
            risk=risk,
            recommended_action={"action": action, "target": target or None, "rationale": rationale},
        )
