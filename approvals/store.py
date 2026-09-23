"""Human-in-the-loop approval.

Policy can return APPROVAL for a *consequential* action — deleting data, sending
mail, anything you don't want an agent doing unsupervised. Sprint 5 makes that
real: the call is **held**, not run, until a person decides.

Key design choice: approval is by **consequence, not by step**. Routine reads
flow straight through; only the actions a policy marks for approval land in this
queue. Escalating everything would train humans to rubber-stamp — the opposite of
security.

On approval the held call executes and is audited as `approved by <person>`; on
denial it's blocked and audited as `denied by <person>`. Either way the decision,
and who made it, is in the tamper-evident log — threaded into the same run/trace
as the original request.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from audit.trace import RunContext


@dataclass
class ApprovalRequest:
    id: str
    run: RunContext
    agent_id: str
    agent_name: str
    tool: str
    params: dict[str, Any]
    intent_name: str | None
    reason: str
    status: str = "pending"  # pending | approved | denied
    decided_by: str | None = None
    created_at: float = field(default_factory=time.time)


@dataclass
class ApprovalOutcome:
    request: ApprovalRequest
    result: Any | None
    event: Any  # AuditEvent


class ApprovalService:
    """Holds pending approvals and executes (or blocks) them on a human decision."""

    def __init__(self, registry, audit) -> None:
        self.registry = registry
        self.audit = audit
        self._reqs: dict[str, ApprovalRequest] = {}

    def submit(
        self, *, run: RunContext, agent_id: str, agent_name: str, tool: str,
        params: dict[str, Any], intent_name: str | None, reason: str,
    ) -> ApprovalRequest:
        rid = f"appr_{uuid.uuid4().hex[:12]}"
        req = ApprovalRequest(
            id=rid, run=run, agent_id=agent_id, agent_name=agent_name,
            tool=tool, params=dict(params), intent_name=intent_name, reason=reason,
        )
        self._reqs[rid] = req
        return req

    def get(self, request_id: str) -> ApprovalRequest | None:
        return self._reqs.get(request_id)

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._reqs.values() if r.status == "pending"]

    def all(self) -> list[ApprovalRequest]:
        return list(self._reqs.values())

    def approve(self, request_id: str, approver: str) -> ApprovalOutcome:
        req = self._require_pending(request_id)
        result = self.registry.call(req.tool, **req.params)  # NOW it runs
        req.status = "approved"
        req.decided_by = approver
        event = self.audit.append(
            run=req.run, agent_name=req.agent_name, tool=req.tool, params=req.params,
            decision="ALLOW", reason=f"[approval] approved by {approver}", outcome="executed",
        )
        return ApprovalOutcome(req, result, event)

    def deny(self, request_id: str, approver: str) -> ApprovalOutcome:
        req = self._require_pending(request_id)
        req.status = "denied"
        req.decided_by = approver
        event = self.audit.append(
            run=req.run, agent_name=req.agent_name, tool=req.tool, params=req.params,
            decision="DENY", reason=f"[approval] denied by {approver}", outcome="blocked",
        )
        return ApprovalOutcome(req, None, event)

    def _require_pending(self, request_id: str) -> ApprovalRequest:
        req = self._reqs.get(request_id)
        if req is None:
            raise KeyError(f"unknown approval request: {request_id}")
        if req.status != "pending":
            raise ValueError(f"approval {request_id} already {req.status}")
        return req
