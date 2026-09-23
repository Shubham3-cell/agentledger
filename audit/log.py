"""Tamper-evident audit log (Sprint 4 — evidence-grade).

Each event is:
- **traceable** — carries trace_id / run_id / agent_id, so the log reconstructs
  as a distributed trace of agent actions (audit/trace.py);
- **chained** — stores the SHA-256 hash of the previous event, so any edit or
  mid-chain deletion breaks every later hash;
- **signed** — Ed25519, so events can't be forged without the signing key;
- **anchored** — after each append the chain head is written to an external WORM
  witness (audit/anchor.py), so *truncation* (deleting the tail) is detectable
  too.

The canonical bytes hashed and signed are the event's JSON with sorted keys and
no whitespace, excluding the derived hash/signature fields — reproducible on any
machine.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit.anchor import WormAnchor
from audit.trace import RunContext

GENESIS_HASH = "0" * 64


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class AuditEvent:
    seq: int
    timestamp: float
    trace_id: str
    run_id: str
    agent_id: str
    agent_name: str
    tool: str
    params: dict[str, Any]
    decision: str
    reason: str
    outcome: str
    prev_hash: str
    this_hash: str = ""
    signature: str = ""

    def _body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("this_hash", None)
        d.pop("signature", None)
        return d

    def compute_hash(self) -> str:
        return hashlib.sha256(_canonical_bytes(self._body())).hexdigest()


class AuditLog:
    def __init__(
        self,
        path: str | Path,
        private_key: Ed25519PrivateKey,
        anchor: WormAnchor | None = None,
    ) -> None:
        self.path = Path(path)
        self._key = private_key
        self._anchor = anchor
        self._seq = 0
        self._last_hash = GENESIS_HASH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._resume()

    def _resume(self) -> None:
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last is not None:
            self._seq = last["seq"] + 1
            self._last_hash = last["this_hash"]

    def append(
        self,
        *,
        run: RunContext,
        agent_name: str,
        tool: str,
        params: dict[str, Any],
        decision: str,
        reason: str,
        outcome: str,
    ) -> AuditEvent:
        event = AuditEvent(
            seq=self._seq,
            timestamp=time.time(),
            trace_id=run.trace_id,
            run_id=run.run_id,
            agent_id=run.agent_id,
            agent_name=agent_name,
            tool=tool,
            params=params,
            decision=decision,
            reason=reason,
            outcome=outcome,
            prev_hash=self._last_hash,
        )
        event.this_hash = event.compute_hash()
        event.signature = self._key.sign(bytes.fromhex(event.this_hash)).hex()

        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(event)) + "\n")

        # External witness: record the new head so truncation can't hide it.
        if self._anchor is not None:
            self._anchor.anchor(event.seq, event.this_hash)

        self._seq += 1
        self._last_hash = event.this_hash
        return event


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    error: str | None = None


def _load(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def verify_log(path: str | Path, public_key: Ed25519PublicKey) -> VerifyResult:
    """Internal consistency: chain links, content hashes, signatures."""
    events = _load(path)
    prev = GENESIS_HASH
    for i, ev in enumerate(events):
        if ev["seq"] != i:
            return VerifyResult(False, i, f"seq gap at index {i}: got {ev['seq']}")
        if ev["prev_hash"] != prev:
            return VerifyResult(False, i, f"broken chain at seq {ev['seq']}")
        body = {k: v for k, v in ev.items() if k not in ("this_hash", "signature")}
        if hashlib.sha256(_canonical_bytes(body)).hexdigest() != ev["this_hash"]:
            return VerifyResult(False, i, f"content tampered at seq {ev['seq']}")
        try:
            public_key.verify(bytes.fromhex(ev["signature"]), bytes.fromhex(ev["this_hash"]))
        except InvalidSignature:
            return VerifyResult(False, i, f"bad signature at seq {ev['seq']}")
        prev = ev["this_hash"]
    return VerifyResult(True, len(events))


def verify_evidence(
    path: str | Path, public_key: Ed25519PublicKey, anchor: WormAnchor
) -> VerifyResult:
    """Full evidence check: internal consistency AND the external anchor.

    Catches truncation — a tail the internal chain alone would accept, because
    the WORM witness still knows a sequence number the log no longer contains.
    """
    inner = verify_log(path, public_key)
    if not inner.ok:
        return inner

    latest = anchor.latest()
    if latest is None:
        return VerifyResult(True, inner.checked)  # nothing anchored yet

    events = _load(path)
    heads = {ev["seq"]: ev["this_hash"] for ev in events}
    if latest.seq not in heads:
        return VerifyResult(
            False, inner.checked,
            f"truncated: anchor witnesses seq {latest.seq}, log ends at "
            f"{max(heads) if heads else -1}",
        )
    if heads[latest.seq] != latest.head_hash:
        return VerifyResult(False, inner.checked, f"anchor head mismatch at seq {latest.seq}")
    return VerifyResult(True, inner.checked)
