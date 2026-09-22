"""Tool registry.

Sprint 1's gateway asked a single hard-coded server "do you have this tool?".
That doesn't scale past one server and it hides *what a tool needs*. The
registry makes the tool surface explicit: every tool is declared once, with

- which **server** handles it (so the gateway can route), and
- the **scope** a caller's credential must hold to use it (least privilege).

Nothing routes or authorises against a tool that isn't registered — an unknown
tool is refused, not guessed at.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class MCPServer(Protocol):
    def has_tool(self, name: str) -> bool: ...
    def call(self, name: str, **params: Any) -> Any: ...


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    required_scope: str
    server: MCPServer


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list_for_scopes(self, scopes: frozenset[str]) -> list[str]:
        """Which registered tools a set of scopes can reach — the caller's surface."""
        return sorted(n for n, t in self._tools.items() if t.required_scope in scopes)

    def call(self, name: str, **params: Any) -> Any:
        spec = self._tools[name]
        return spec.server.call(name, **params)
