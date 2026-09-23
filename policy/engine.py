"""Policy engine — deterministic ALLOW / DENY / APPROVAL, now argument-aware.

Sprint 3 upgrades rules from "tool -> effect" to "tool + argument conditions ->
effect". A rule grants an effect only when its per-parameter conditions hold, so
policy can say "read_file is allowed, but only under /reports/" or "send_email
needs approval, and only to @company.com".

Rules shape (per role)::

    roles:
      operator:
        rules:
          - { tool: read_file,  effect: allow,    where: { path: { starts_with: "/reports/" } } }
          - { tool: delete_file, effect: approval, where: { path: { starts_with: "/reports/" } } }

Precedence: any satisfied ALLOW wins; else any satisfied APPROVAL; else DENY.
Default deny still holds — nothing runs unless a rule explicitly grants it. When
a rule matches the tool but its conditions fail, the denial names the failing
argument, so the audit log explains *why*, not just *that*.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from agents.identity import Agent
from policy.conditions import check_conditions


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL = "APPROVAL"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str


class PolicyEngine:
    def __init__(self, rules: dict) -> None:
        self._roles: dict = rules.get("roles", {})

    def evaluate(self, agent: Agent, tool: str, params: dict | None = None) -> PolicyResult:
        params = params or {}
        allow_reason: str | None = None
        approval_reason: str | None = None
        condition_failures: list[str] = []

        for role in agent.roles:
            for rule in self._roles.get(role, {}).get("rules", []):
                if rule.get("tool") != tool:
                    continue
                ok, detail = check_conditions(rule.get("where", {}), params)
                if not ok:
                    condition_failures.append(f"[{role}] {detail}")
                    continue
                effect = rule.get("effect", "deny")
                note = f" ({detail})" if rule.get("where") else ""
                if effect == "allow" and allow_reason is None:
                    allow_reason = f"'{tool}' allowed by role '{role}'{note}"
                elif effect == "approval" and approval_reason is None:
                    approval_reason = f"'{tool}' requires approval — role '{role}'{note}"

        if allow_reason:
            return PolicyResult(Decision.ALLOW, allow_reason)
        if approval_reason:
            return PolicyResult(Decision.APPROVAL, approval_reason)
        if condition_failures:
            return PolicyResult(
                Decision.DENY,
                f"'{tool}' argument not permitted: {'; '.join(condition_failures)}",
            )
        return PolicyResult(
            Decision.DENY,
            f"default deny: no role of {agent.name} permits '{tool}'",
        )
