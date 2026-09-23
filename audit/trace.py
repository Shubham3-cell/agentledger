"""Distributed-trace context for the audit log.

Sprint 1-3 attributed each event to an agent. Sprint 4 gives the evidence the
shape of a distributed trace: every event carries a **trace** (one end-to-end
request), a **run** (one task/invocation), and the **agent** that acted. That
hierarchy is what lets you reconstruct "everything agent X did during run Y of
trace Z" from the log after the fact — the OpenTelemetry model, applied to agent
actions instead of microservice spans.

A RunContext is created once per task and shared by every tool call in it, so
the whole task threads together under one run_id and trace_id.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


@dataclass(frozen=True)
class RunContext:
    """Identifies one task: which agent, under which run, within which trace."""

    agent_id: str
    trace_id: str = field(default_factory=lambda: _id("trace"))
    run_id: str = field(default_factory=lambda: _id("run"))


def new_run(agent_id: str) -> RunContext:
    return RunContext(agent_id=agent_id)
