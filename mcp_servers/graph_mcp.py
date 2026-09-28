"""A REAL MCP-style server backed by Microsoft Graph (Sprint 7).

Unlike the fake file/mail servers, this one authenticates to *your* Entra tenant
with an app registration (client credentials) and makes real Graph calls. It's
still wired behind the AgentLedger gateway, so every call passes auth -> scope ->
intent -> policy before it's allowed to run.

Credentials are read from the environment so no secret is ever hard-coded:
    AL_TENANT_ID     - your Directory (tenant) ID
    AL_CLIENT_ID     - the app registration's Application (client) ID
    AL_CLIENT_SECRET - a client secret value (kept out of git)

Read-only tools used in the lab:
    list_users     -> GET /users            (needs Directory.Read.All)
    read_signins   -> GET /auditLogs/signIns (needs AuditLog.Read.All)

A deliberately destructive tool is defined but NEVER runs in the investigate
demo — the intent gate blocks it, and policy marks it approval-only:
    disable_user   -> PATCH /users/{id}  accountEnabled=false
"""
from __future__ import annotations

import os
from typing import Any

import requests

try:
    import msal
except ImportError:  # pragma: no cover
    msal = None

GRAPH = "https://graph.microsoft.com/v1.0"
_SCOPE = ["https://graph.microsoft.com/.default"]


class GraphMCPServer:
    """Talks to Microsoft Graph with an app-only (client credentials) token."""

    def __init__(self, tenant_id: str | None = None, client_id: str | None = None,
                 client_secret: str | None = None) -> None:
        self.tenant_id = tenant_id or os.environ.get("AL_TENANT_ID")
        self.client_id = client_id or os.environ.get("AL_CLIENT_ID")
        self.client_secret = client_secret or os.environ.get("AL_CLIENT_SECRET")
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise RuntimeError(
                "Missing Entra credentials. Set AL_TENANT_ID, AL_CLIENT_ID, "
                "AL_CLIENT_SECRET (see lab_secrets.example)."
            )
        if msal is None:
            raise RuntimeError("msal not installed — run: pip install msal requests")
        self._app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            client_credential=self.client_secret,
        )
        self._tools = {"list_users", "read_signins", "disable_user"}

    # --- token ---
    def _token(self) -> str:
        res = self._app.acquire_token_for_client(scopes=_SCOPE)
        if "access_token" not in res:
            raise RuntimeError(f"token error: {res.get('error_description', res)}")
        return res["access_token"]

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = requests.get(f"{GRAPH}{path}",
                         headers={"Authorization": f"Bearer {self._token()}"},
                         params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    # --- MCP interface ---
    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def call(self, name: str, **params: Any) -> Any:
        if name == "list_users":
            data = self._get("/users", {"$select": "displayName,userPrincipalName", "$top": 10})
            return [u["userPrincipalName"] for u in data.get("value", [])]
        if name == "read_signins":
            data = self._get("/auditLogs/signIns", {"$top": params.get("top", 5)})
            return [
                {"user": s.get("userPrincipalName"),
                 "app": s.get("appDisplayName"),
                 "status": s.get("status", {}).get("errorCode"),
                 "time": s.get("createdDateTime")}
                for s in data.get("value", [])
            ]
        if name == "disable_user":
            # Real capability, but gated: intent blocks it in the investigate task,
            # and policy marks it approval-only. Guarded so the lab never disables
            # anyone by accident.
            upn = params["userPrincipalName"]
            if not params.get("confirm"):
                return f"[dry-run] would disable {upn} (pass confirm=True to actually PATCH)"
            r = requests.patch(
                f"{GRAPH}/users/{upn}",
                headers={"Authorization": f"Bearer {self._token()}",
                         "Content-Type": "application/json"},
                json={"accountEnabled": False}, timeout=30)
            r.raise_for_status()
            return f"disabled {upn}"
        raise KeyError(f"unknown tool: {name}")
