"""The MCP Gateway — one controlled execution boundary (Sprint 2).

The caller no longer hands in an Agent it claims to be. It presents a **token**,
and the gateway proves the identity from it. The full order of checks:

    authenticate  ->  resolve tool  ->  scope check  ->  policy  ->  (execute | hold | block)  ->  audit

Each gate can stop the call, and *every* outcome — including a rejected token —
is written to the tamper-evident audit log, attributed to the identity the token
actually proved (or "unauthenticated" when it proved nothing). Nothing reaches a
backend server that wasn't authenticated, in-scope, and policy-allowed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from audit.log import AuditEvent, AuditLog
from gateway.auth import AuthError, AuthService
from gateway.registry import ToolRegistry
from policy.engine import Decision, PolicyEngine

UNAUTHENTICATED = "unauthenticated"


@dataclass
class CallResult:
    decision: Decision
    stage: str  # auth | scope | registry | policy | execute
    outcome: str  # executed | blocked | pending_approval
    reason: str
    result: Any | None
    event: AuditEvent


class Gateway:
    def __init__(
        self,
        auth: AuthService,
        registry: ToolRegistry,
        policy: PolicyEngine,
        audit: AuditLog,
    ) -> None:
        self.auth = auth
        self.registry = registry
        self.policy = policy
        self.audit = audit

    def handle(self, token: str | None, tool: str, **params: Any) -> CallResult:
        # 1. AUTHENTICATE — prove who is calling. No trust in a claimed identity.
        try:
            principal = self.auth.authenticate(token)
        except AuthError as exc:
            return self._finish(
                agent_id=UNAUTHENTICATED, agent_name=UNAUTHENTICATED,
                tool=tool, params=params, decision=Decision.DENY,
                stage="auth", outcome="blocked",
                reason=f"authentication failed: {exc}", result=None,
            )

        agent = principal.agent

        # 2. RESOLVE — the tool must be a registered one.
        spec = self.registry.get(tool)
        if spec is None:
            return self._finish(
                agent_id=agent.agent_id, agent_name=agent.name,
                tool=tool, params=params, decision=Decision.DENY,
                stage="registry", outcome="blocked",
                reason=f"unknown tool '{tool}' (not in registry)", result=None,
            )

        # 3. SCOPE — least privilege: the credential must grant the tool's scope.
        if spec.required_scope not in principal.scopes:
            return self._finish(
                agent_id=agent.agent_id, agent_name=agent.name,
                tool=tool, params=params, decision=Decision.DENY,
                stage="scope", outcome="blocked",
                reason=f"scope '{spec.required_scope}' not granted to this credential",
                result=None,
            )

        # 4. POLICY — deterministic ALLOW / DENY / APPROVAL, default deny.
        verdict = self.policy.evaluate(agent, tool, params)
        if verdict.decision is Decision.DENY:
            return self._finish(
                agent_id=agent.agent_id, agent_name=agent.name,
                tool=tool, params=params, decision=Decision.DENY,
                stage="policy", outcome="blocked", reason=verdict.reason, result=None,
            )
        if verdict.decision is Decision.APPROVAL:
            return self._finish(
                agent_id=agent.agent_id, agent_name=agent.name,
                tool=tool, params=params, decision=Decision.APPROVAL,
                stage="policy", outcome="pending_approval",
                reason=verdict.reason, result=None,
            )

        # 5. EXECUTE — routed through the registry to the owning server.
        result = self.registry.call(tool, **params)
        return self._finish(
            agent_id=agent.agent_id, agent_name=agent.name,
            tool=tool, params=params, decision=Decision.ALLOW,
            stage="execute", outcome="executed", reason=verdict.reason, result=result,
        )

    def _finish(
        self, *, agent_id: str, agent_name: str, tool: str, params: dict,
        decision: Decision, stage: str, outcome: str, reason: str, result: Any,
    ) -> CallResult:
        event = self.audit.append(
            agent_id=agent_id, agent_name=agent_name, tool=tool, params=params,
            decision=decision.value, reason=f"[{stage}] {reason}", outcome=outcome,
        )
        return CallResult(decision, stage, outcome, reason, result, event)
