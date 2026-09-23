"""The MCP Gateway — one controlled execution boundary (Sprint 4).

    authenticate -> resolve -> scope -> intent -> policy(args) -> (execute | hold | block) -> audit

Every call runs within a **RunContext** (trace_id / run_id / agent_id), so the
audit events of a task thread together as one trace. Every outcome — including a
rejected token, an out-of-intent call, or a disallowed argument — is written to
the tamper-evident, anchored audit log.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.intent import Intent
from audit.log import AuditEvent, AuditLog
from audit.trace import RunContext
from gateway.auth import AuthError, AuthService
from gateway.registry import ToolRegistry
from policy.engine import Decision, PolicyEngine

UNAUTHENTICATED = "unauthenticated"


@dataclass
class CallResult:
    decision: Decision
    stage: str  # auth | registry | scope | intent | policy | execute
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

    def handle(
        self,
        token: str | None,
        tool: str,
        *,
        intent: Intent | None = None,
        run: RunContext | None = None,
        **params: Any,
    ) -> CallResult:
        # 1. AUTHENTICATE
        try:
            principal = self.auth.authenticate(token)
        except AuthError as exc:
            return self._finish(
                UNAUTHENTICATED, UNAUTHENTICATED, run, tool, params, intent,
                Decision.DENY, "auth", "blocked", f"authentication failed: {exc}", None,
            )
        agent = principal.agent

        # 2. RESOLVE
        spec = self.registry.get(tool)
        if spec is None:
            return self._finish(
                agent.agent_id, agent.name, run, tool, params, intent,
                Decision.DENY, "registry", "blocked",
                f"unknown tool '{tool}' (not in registry)", None,
            )

        # 3. SCOPE
        if spec.required_scope not in principal.scopes:
            return self._finish(
                agent.agent_id, agent.name, run, tool, params, intent,
                Decision.DENY, "scope", "blocked",
                f"scope '{spec.required_scope}' not granted to this credential", None,
            )

        # 4. INTENT
        if intent is not None and not intent.permits(tool):
            return self._finish(
                agent.agent_id, agent.name, run, tool, params, intent,
                Decision.DENY, "intent", "blocked",
                f"'{tool}' outside task intent '{intent.name}' ({intent.purpose})", None,
            )

        # 5. POLICY
        verdict = self.policy.evaluate(agent, tool, params)
        if verdict.decision is Decision.DENY:
            return self._finish(
                agent.agent_id, agent.name, run, tool, params, intent,
                Decision.DENY, "policy", "blocked", verdict.reason, None,
            )
        if verdict.decision is Decision.APPROVAL:
            return self._finish(
                agent.agent_id, agent.name, run, tool, params, intent,
                Decision.APPROVAL, "policy", "pending_approval", verdict.reason, None,
            )

        # 6. EXECUTE
        result = self.registry.call(tool, **params)
        return self._finish(
            agent.agent_id, agent.name, run, tool, params, intent,
            Decision.ALLOW, "execute", "executed", verdict.reason, result,
        )

    def _finish(
        self, agent_id: str, agent_name: str, run: RunContext | None, tool: str,
        params: dict, intent: Intent | None, decision: Decision, stage: str,
        outcome: str, reason: str, result: Any,
    ) -> CallResult:
        # Thread this event into the task's trace/run (or start a fresh one).
        if run is None:
            ctx = RunContext(agent_id=agent_id)
        else:
            ctx = RunContext(agent_id=agent_id, trace_id=run.trace_id, run_id=run.run_id)
        intent_tag = f" intent={intent.name}" if intent is not None else ""
        event = self.audit.append(
            run=ctx, agent_name=agent_name, tool=tool, params=params,
            decision=decision.value, reason=f"[{stage}{intent_tag}] {reason}", outcome=outcome,
        )
        return CallResult(decision, stage, outcome, reason, result, event)
