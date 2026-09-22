"""Agent identity.

Every agent that talks to the outside world through AgentLedger gets its own
stable identity. Nothing runs anonymously: an agent's id is what the policy
engine authorises against and what every audit event is attributed to.

In the MVP an identity is a name + a set of roles + a generated agent_id.
In Sprint 2 this is where real credentials (Entra workload identity, scoped
tokens) get attached — the shape stays the same.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Agent:
    """A named actor with scoped roles. The unit the policy engine reasons about."""

    name: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    agent_id: str = field(default_factory=lambda: f"agent_{uuid.uuid4().hex[:12]}")

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.name}<{self.agent_id}>"


def new_agent(name: str, roles: list[str] | None = None) -> Agent:
    """Mint an agent identity. Roles drive what the policy engine will allow."""
    return Agent(name=name, roles=tuple(roles or []))
