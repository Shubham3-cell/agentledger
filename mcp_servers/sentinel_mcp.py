"""A simulated Microsoft Sentinel / Defender MCP server (Deliverable 3).

IMPLEMENTED HERE: an MCP-style SOC tool surface — list / get incidents, read an
incident's entities, and a consequential `isolate_device` response action — backed
by in-memory SIMULATED incident data. This lets the AgentLedger gateway and a SOC
agent be exercised end-to-end with no Azure, no cost and no real security data.

NOT REAL: the incidents below are synthetic stand-ins. In production these calls
would hit the Microsoft Sentinel / Defender APIs. The reusable, real part is
everything *around* the call — identity, scope, intent, policy and tamper-evident
audit — which is why the agent must come through the gateway to reach any of it.
"""
from __future__ import annotations

from typing import Any

# --- SIMULATED incident data (synthetic — not real telemetry) ---
_INCIDENTS: dict[str, dict[str, Any]] = {
    "INC-4471": {
        "id": "INC-4471",
        "title": "Password spray against finance users",
        "severity": "High",
        "status": "Active",
        "created": "2026-10-02T03:14:00Z",
        "entities": {
            "accounts": ["j.smith@contoso.com", "a.lee@contoso.com"],
            "ips": ["203.0.113.45"],
            "devices": ["FIN-LT-014"],
        },
        "alerts": ["Password spray detected (T1110.003)"],
    },
    "INC-4472": {
        "id": "INC-4472",
        "title": "Legacy-auth sign-in from new country",
        "severity": "Medium",
        "status": "Active",
        "created": "2026-10-02T04:01:00Z",
        "entities": {
            "accounts": ["m.khan@contoso.com"],
            "ips": ["198.51.100.23"],
            "devices": [],
        },
        "alerts": ["Legacy authentication sign-in (T1078)"],
    },
}


class SentinelMCPServer:
    """MCP-style SOC tool surface over simulated Sentinel / Defender data."""

    def __init__(self) -> None:
        self._incidents = {k: dict(v) for k, v in _INCIDENTS.items()}
        self._isolated: list[str] = []  # devices "isolated" in this simulation
        self._tools = {
            "list_incidents",
            "get_incident",
            "get_incident_entities",
            "isolate_device",
        }

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def call(self, name: str, **params: Any) -> Any:
        if name == "list_incidents":
            return [
                {"id": i["id"], "title": i["title"],
                 "severity": i["severity"], "status": i["status"]}
                for i in self._incidents.values()
            ]
        if name == "get_incident":
            inc = self._incidents.get(params["incident_id"])
            if inc is None:
                raise KeyError(f"unknown incident {params['incident_id']}")
            return inc
        if name == "get_incident_entities":
            inc = self._incidents.get(params["incident_id"])
            if inc is None:
                raise KeyError(f"unknown incident {params['incident_id']}")
            return inc["entities"]
        if name == "isolate_device":
            device = params["device"]
            self._isolated.append(device)
            return f"[SIMULATED] isolated device {device}"
        raise KeyError(f"unknown tool: {name}")
