"""A second fake MCP server — mail.

Its only job in the MVP is to prove the tool registry actually *routes*: with two
servers registered, the gateway has to send `read_file` to the files server and
`send_email` to this one. One boundary, many backends.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    handler: Callable[..., Any]


class MailMCPServer:
    def __init__(self) -> None:
        self._sent: list[dict[str, str]] = []
        self._inbox = [
            {"from": "alerts@example.com", "subject": "Nightly backup OK"},
            {"from": "security@example.com", "subject": "New sign-in detected"},
        ]
        self._tools: dict[str, Tool] = {
            "list_inbox": Tool("list_inbox", "List inbox messages", self._list_inbox),
            "send_email": Tool("send_email", "Send an email (outbound)", self._send_email),
        }

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def call(self, name: str, **params: Any) -> Any:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name].handler(**params)

    def _list_inbox(self) -> list[dict[str, str]]:
        return list(self._inbox)

    def _send_email(self, to: str, subject: str) -> str:
        self._sent.append({"to": to, "subject": subject})
        return f"sent to {to}"
