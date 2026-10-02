"""AI SOC triage agent — investigates an incident THROUGH the gateway.

The agent reads incident evidence via the AgentLedger gateway (so every read is
authenticated, scoped, intent-bounded and audited), reasons over it, and produces
a triage report with a RECOMMENDED action. The agent never executes a response
itself: a consequential action (isolate a device, reset credentials) must be
proposed under a response intent and HELD for human approval by the gateway.

AI recommends; gateway + human dispose. That separation is the whole point.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.intent import Intent
from policy.engine import Decision
from soc.reasoner import Assessment, Reasoner, RuleBasedReasoner

CONSEQUENTIAL = {"isolate_device", "reset_credentials"}


@dataclass
class TriageReport:
    incident_id: str
    title: str
    severity: str
    summary: str
    findings: list[str]
    recommended_action: dict
    requires_human_approval: bool


class TriageAgent:
    """Reads evidence via the gateway and recommends — it cannot act on its own."""

    def __init__(self, gateway, token: str, intent: Intent, reasoner: Reasoner | None = None) -> None:
        self.gateway = gateway
        self.token = token
        self.intent = intent
        self.reasoner = reasoner or RuleBasedReasoner()

    def _read(self, tool: str, **params: Any) -> Any:
        res = self.gateway.handle(self.token, tool, intent=self.intent, **params)
        if res.decision is not Decision.ALLOW:
            raise PermissionError(f"gateway denied '{tool}' at {res.stage}: {res.reason}")
        return res.result

    def triage(self, incident_id: str) -> TriageReport:
        incident = self._read("get_incident", incident_id=incident_id)
        entities = self._read("get_incident_entities", incident_id=incident_id)
        a: Assessment = self.reasoner.assess(incident, entities)
        findings = [
            f"Accounts involved: {', '.join(entities.get('accounts') or []) or 'none'}",
            f"Source IPs: {', '.join(entities.get('ips') or []) or 'none'}",
            f"Devices: {', '.join(entities.get('devices') or []) or 'none'}",
            f"Alerts: {', '.join(incident.get('alerts', [])) or 'none'}",
        ]
        return TriageReport(
            incident_id=incident_id,
            title=incident.get("title", ""),
            severity=incident.get("severity", ""),
            summary=a.summary,
            findings=findings,
            recommended_action=a.recommended_action,
            requires_human_approval=a.recommended_action.get("action") in CONSEQUENTIAL,
        )
