"""A fake MCP server.

The whole MVP deliberately runs against this stand-in instead of a real MCP
server. That is a scope decision, not a shortcut: the security value of
AgentLedger is in the gateway / policy / audit layer *around* tool calls, and a
fake server lets that layer be demonstrated end-to-end without depending on
Entra, Defender or Intune being wired up (that is Sprint 6, the stretch).

It exposes a tiny tool registry. Each tool is just a Python callable with a
name. `delete_file` is intentionally destructive so the demo has something the
policy engine should refuse by default.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    handler: Callable[..., Any]


class FakeMCPServer:
    """Minimal MCP-like tool host: a named registry the gateway can route into."""

    def __init__(self) -> None:
        self._files: dict[str, str] = {
            "notes.txt": "hello from the fake filesystem",
            "budget.csv": "item,amount\ncoffee,4.50",
        }
        self._tools: dict[str, Tool] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(Tool("list_files", "List file names", self._list_files))
        self.register(Tool("read_file", "Read a file's contents", self._read_file))
        self.register(Tool("delete_file", "Delete a file (destructive)", self._delete_file))

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def list_tools(self) -> list[str]:
        return sorted(self._tools)

    def call(self, name: str, **params: Any) -> Any:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name].handler(**params)

    # --- tool handlers ---
    def _list_files(self) -> list[str]:
        return sorted(self._files)

    def _read_file(self, path: str) -> str:
        if path not in self._files:
            raise FileNotFoundError(path)
        return self._files[path]

    def _delete_file(self, path: str) -> str:
        self._files.pop(path, None)
        return f"deleted {path}"
