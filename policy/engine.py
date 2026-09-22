"""Policy engine — the heart of AgentLedger.

One rule above all: **default deny**. If nothing explicitly allows a tool call,
the answer is DENY. On top of that, some tools are allowed outright and some are
allowed only *with a human approval*.

A decision is deterministic: same (agent, tool, params) in, same decision out.
That determinism is what makes the audit trail meaningful later — you can always
explain *why* a call was allowed or blocked.

The MVP reads rules from a plain dict (loaded from policy.yaml in the demo).
Sprint 3 deepens this with intent scoping and per-parameter conditions; the
ALLOW / DENY / APPROVAL contract stays exactly this.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from agents.identity import Agent


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL = "APPROVAL"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str


class PolicyEngine:
    """Deterministic ALLOW / DENY / APPROVAL decisions. Default deny.

    Rules shape::

        {
          "roles": {
            "reader":  {"allow": ["list_files", "read_file"]},
            "operator": {"allow": ["list_files", "read_file"],
                         "approval": ["delete_file"]},
          }
        }

    A tool is ALLOWed if any of the agent's roles allow it. Otherwise, if any
    role marks it for approval, the decision is APPROVAL. Otherwise DENY.
    """

    def __init__(self, rules: dict) -> None:
        self._roles: dict = rules.get("roles", {})

    def evaluate(self, agent: Agent, tool: str, params: dict | None = None) -> PolicyResult:
        allowed_by: list[str] = []
        approval_by: list[str] = []

        for role in agent.roles:
            spec = self._roles.get(role, {})
            if tool in spec.get("allow", []):
                allowed_by.append(role)
            if tool in spec.get("approval", []):
                approval_by.append(role)

        if allowed_by:
            return PolicyResult(
                Decision.ALLOW,
                f"'{tool}' allowed by role(s): {', '.join(allowed_by)}",
            )
        if approval_by:
            return PolicyResult(
                Decision.APPROVAL,
                f"'{tool}' requires human approval (role(s): {', '.join(approval_by)})",
            )
        return PolicyResult(
            Decision.DENY,
            f"default deny: no role of {agent.name} permits '{tool}'",
        )
