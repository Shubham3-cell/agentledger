"""Per-parameter condition evaluation.

Sprint 1-2 policy answered "may this agent use this tool?". That's coarse: an
agent allowed to `read_file` could read *any* file, and one allowed to
`send_email` could mail *anyone*. Real authorization constrains the arguments —
`read_file` only under `/reports/`, `send_email` only to `@company.com`.

A condition is a small, deterministic spec on a parameter::

    where:
      path: { starts_with: "/reports/" }
      to:   { ends_with: "@company.com" }

All conditions must hold (AND). A **missing** parameter fails closed — you can't
satisfy a constraint on an argument you didn't supply. Determinism is the whole
point: the same call always yields the same verdict, which is what keeps the
audit trail explainable.
"""
from __future__ import annotations

import re
from typing import Any

Number = (int, float)


def _apply(op: str, value: Any, expected: Any) -> bool:
    if op == "equals":
        return value == expected
    if op == "not_equals":
        return value != expected
    if op == "starts_with":
        return isinstance(value, str) and value.startswith(expected)
    if op == "ends_with":
        return isinstance(value, str) and value.endswith(expected)
    if op == "contains":
        return isinstance(value, str) and expected in value
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op == "matches":
        return isinstance(value, str) and re.fullmatch(expected, value) is not None
    if op == "max":
        return isinstance(value, Number) and value <= expected
    if op == "min":
        return isinstance(value, Number) and value >= expected
    raise ValueError(f"unknown condition operator: {op}")


def check_conditions(where: dict[str, dict], params: dict[str, Any]) -> tuple[bool, str]:
    """Return (ok, human-readable detail). Fails closed on a missing parameter."""
    if not where:
        return True, "no constraints"
    for param_name, spec in where.items():
        if param_name not in params:
            return False, f"missing parameter '{param_name}'"
        value = params[param_name]
        for op, expected in spec.items():
            if not _apply(op, value, expected):
                return False, f"'{param_name}'={value!r} failed [{op} {expected!r}]"
    return True, "all parameter conditions met"
