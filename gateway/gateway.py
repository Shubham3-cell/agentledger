"""The MCP Gateway — one controlled execution boundary (Sprint 5).

    authenticate -> resolve -> scope -> intent -> policy(args) -> (execute | HOLD | block) -> audit

When policy returns APPROVAL, the call is submitted to the approval service and
**held** — it runs only after a human approves it. Every call runs within a
RunContext (trace/run/agent) and every outcome is written to the tamper-evident,
anchored audit log.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.intent import Intent
from approvals.store import ApprovalService
from audit.log import AuditEvent, AuditLog
from audit.trace import RunContext
from gateway.auth import AuthError, AuthService
from gateway.registry import ToolRegistry
from policy.engine import Decision, PolicyEngine

UNAUTHENTICATED = "unauthenticated"


@dataclass
class CallResult:
    decision: Decision
    stage: str
    outcome: str  # executed | blocked | pending_approval
    reason: str
    result: Any | None
    event: AuditEvent
    approval_id: str | None = None


class Gateway:
    def __init__(
        self,
        auth: AuthService,
        registry: ToolRegistry,
        policy: PolicyEngine,
        audit: AuditLog,
        approval: ApprovalService | None = None,
    ) -> None:
        self.auth = auth
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.approval = approval

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
            ctx = self._ctx(UNAUTHENTICATED, run)
            return self._finish(ctx, UNAUTHENTICATED, tool, params, intent,
                                Decision.DENY, "auth", "blocked",
                                f"authentication failed: {exc}", None)
        agent = principal.agent
        ctx = self._ctx(agent.agent_id, run)

        # 2. RESOLVE
        spec = self.registry.get(tool)
        if spec is None:
            return self._finish(ctx, agent.name, tool, params, intent,
                                Decision.DENY, "registry", "blocked",
                                f"unknown tool '{tool}' (not in registry)", None)

        # 3. SCOPE
        if spec.required_scope not in principal.scopes:
            return self._finish(ctx, agent.name, tool, params, intent,
                                Decision.DENY, "scope", "blocked",
                                f"scope '{spec.required_scope}' not granted to this credential", None)

        # 4. INTENT
        if intent is not None and not intent.permits(tool):
            return self._finish(ctx, agent.name, tool, params, intent,
                                Decision.DENY, "intent", "blocked",
                                f"'{tool}' outside task intent '{intent.name}' ({intent.purpose})", None)

        # 5. POLICY
        verdict = self.policy.evaluate(agent, tool, params)
        if verdict.decision is Decision.DENY:
            return self._finish(ctx, agent.name, tool, params, intent,
                                Decision.DENY, "policy", "blocked", verdict.reason, None)

        if verdict.decision is Decision.APPROVAL:
            approval_id = None
            reason = verdict.reason
            if self.approval is not None:
                req = self.approval.submit(
                    run=ctx, agent_id=agent.agent_id, agent_name=agent.name,
                    tool=tool, params=params,
                    intent_name=intent.name if intent else None, reason=verdict.reason,
                )
                approval_id = req.id
                reason = f"{verdict.reason} — held as {approval_id}"
            return self._finish(ctx, agent.name, tool, params, intent,
                                Decision.APPROVAL, "policy", "pending_approval",
                                reason, None, approval_id=approval_id)

        # 6. EXECUTE
        result = self.registry.call(tool, **params)
        return self._finish(ctx, agent.name, tool, params, intent,
                            Decision.ALLOW, "execute", "executed", verdict.reason, result)

    @staticmethod
    def _ctx(agent_id: str, run: RunContext | None) -> RunContext:
        if run is None:
            return RunContext(agent_id=agent_id)
        return RunContext(agent_id=agent_id, trace_id=run.trace_id, run_id=run.run_id)

    def _finish(
        self, ctx: RunContext, agent_name: str, tool: str, params: dict,
        intent: Intent | None, decision: Decision, stage: str, outcome: str,
        reason: str, result: Any, approval_id: str | None = None,
    ) -> CallResult:
        intent_tag = f" intent={intent.name}" if intent is not None else ""
        event = self.audit.append(
            run=ctx, agent_name=agent_name, tool=tool, params=params,
            decision=decision.value, reason=f"[{stage}{intent_tag}] {reason}", outcome=outcome,
        )
        return CallResult(decision, stage, outcome, reason, result, event, approval_id)
