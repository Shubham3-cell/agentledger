"""The MCP Gateway — AgentLedger's single controlled execution boundary.

Every tool call an agent makes goes through here. The gateway does not decide
policy or write crypto itself; it *orchestrates* the three guarantees in order:

    identity  ->  policy decision  ->  (execute | block | hold)  ->  audit event

Nothing reaches the MCP server that wasn't allowed, and nothing happens — allowed
or blocked — without a signed, chained record. That ordering is the product.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.identity import Agent
from audit.log import AuditEvent, AuditLog
from mcp_servers.fake_mcp import FakeMCPServer
from policy.engine import Decision, PolicyEngine


@dataclass
class CallResult:
    decision: Decision
    reason: str
    outcome: str  # executed | blocked | pending_approval
    result: Any | None
    event: AuditEvent


class Gateway:
    def __init__(self, policy: PolicyEngine, audit: AuditLog, mcp: FakeMCPServer) -> None:
        self.policy = policy
        self.audit = audit
        self.mcp = mcp

    def handle(self, agent: Agent, tool: str, **params: Any) -> CallResult:
        # 1. Policy decision (deterministic, default-deny).
        verdict = self.policy.evaluate(agent, tool, params)

        # 2. Act on the decision.
        result: Any | None = None
        if verdict.decision is Decision.ALLOW:
            if not self.mcp.has_tool(tool):
                outcome, reason = "blocked", f"unknown tool '{tool}'"
            else:
                result = self.mcp.call(tool, **params)
                outcome, reason = "executed", verdict.reason
        elif verdict.decision is Decision.APPROVAL:
            # MVP: escalation is recorded and held. Sprint 5 adds the human UI
            # that can release a held call after approval.
            outcome, reason = "pending_approval", verdict.reason
        else:  # DENY
            outcome, reason = "blocked", verdict.reason

        # 3. Write the evidence — always, whatever the decision.
        event = self.audit.append(
            agent_id=agent.agent_id,
            agent_name=agent.name,
            tool=tool,
            params=params,
            decision=verdict.decision.value,
            reason=reason,
            outcome=outcome,
        )

        return CallResult(verdict.decision, reason, outcome, result, event)
