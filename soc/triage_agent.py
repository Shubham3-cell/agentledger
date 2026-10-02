"""AI SOC triage agent — investigates an incident THROUGH the gateway.

The agent reads incident evidence via the AgentLedger gateway (so every read is
authenticated, scoped, intent-bounded and audited), retrieves the relevant
response runbook (RAG), reasons over it all, and produces a triage report with a
RECOMMENDED action. The agent never executes a response itself: a consequential
action (isolate a device, reset credentials) must be proposed under a response
intent and HELD for human approval by the gateway.

AI recommends, grounded in your runbooks; gateway + human dispose.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.intent import Intent
from policy.engine import Decision
from soc.reasoner import Assessment, Reasoner, RuleBasedReasoner
from soc.retriever import RunbookRetriever

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
    runbook: dict | None = None


class TriageAgent:
    """Reads evidence via the gateway, grounds in runbooks, and recommends."""

    def __init__(
        self,
        gateway,
        token: str,
        intent: Intent,
        reasoner: Reasoner | None = None,
        retriever: RunbookRetriever | None = None,
    ) -> None:
        self.gateway = gateway
        self.token = token
        self.intent = intent
        self.reasoner = reasoner or RuleBasedReasoner()
        self.retriever = retriever or RunbookRetriever()

    def _read(self, tool: str, **params: Any) -> Any:
        res = self.gateway.handle(self.token, tool, intent=self.intent, **params)
        if res.decision is not Decision.ALLOW:
            raise PermissionError(f"gateway denied '{tool}' at {res.stage}: {res.reason}")
        return res.result

    def triage(self, incident_id: str) -> TriageReport:
        incident = self._read("get_incident", incident_id=incident_id)
        entities = self._read("get_incident_entities", incident_id=incident_id)
        assessment: Assessment = self.reasoner.assess(incident, entities)

        # RAG: ground the triage in the most relevant response runbook
        query = f"{incident.get('title', '')} {' '.join(incident.get('alerts', []))}"
        hits = self.retriever.retrieve(query, k=1)
        runbook = None
        if hits:
            rb = hits[0]
            runbook = {"name": rb.name, "title": rb.title, "excerpt": rb.text[:240].strip()}

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
            summary=assessment.summary,
            findings=findings,
            recommended_action=assessment.recommended_action,
            requires_human_approval=assessment.recommended_action.get("action") in CONSEQUENTIAL,
            runbook=runbook,
        )
