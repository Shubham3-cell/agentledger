"""Tamper-evident audit log.

Every decision the gateway makes is written here as an event. Two properties
make the log *evidence* rather than just logging:

1. **Hash chain.** Each event carries the SHA-256 hash of the previous event.
   Change any earlier event and every hash after it stops matching — deletion or
   edits in the middle of the chain are detectable, not silent.

2. **Signatures.** Each event is signed with an Ed25519 private key. Even if
   someone could recompute the whole chain, they cannot forge a signature
   without the key. Verification uses only the public key.

The canonical bytes that get hashed and signed are the JSON of the event with
sorted keys and no whitespace, excluding the signature field itself. That
canonicalisation is what makes the hash reproducible on any machine.

In the MVP the log is an append-only JSONL file and the key sits on disk. In
Sprint 4 the chain head is anchored into Azure Blob WORM storage and the key
moves into Key Vault — the event schema and verification logic are unchanged.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_HASH = "0" * 64


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic serialization used for both hashing and signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class AuditEvent:
    seq: int
    timestamp: float
    agent_id: str
    agent_name: str
    tool: str
    params: dict[str, Any]
    decision: str
    reason: str
    outcome: str  # "executed" | "blocked" | "pending_approval"
    prev_hash: str
    this_hash: str = ""
    signature: str = ""  # hex-encoded Ed25519 signature

    def _body(self) -> dict[str, Any]:
        """Everything except the derived hash/signature fields."""
        d = asdict(self)
        d.pop("this_hash", None)
        d.pop("signature", None)
        return d

    def compute_hash(self) -> str:
        return hashlib.sha256(_canonical_bytes(self._body())).hexdigest()


class AuditLog:
    """Append-only, hash-chained, Ed25519-signed event log."""

    def __init__(self, path: str | Path, private_key: Ed25519PrivateKey) -> None:
        self.path = Path(path)
        self._key = private_key
        self._seq = 0
        self._last_hash = GENESIS_HASH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._resume()

    def _resume(self) -> None:
        """Pick up seq/last_hash if the log already has events."""
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
        agent_id: str,
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
            agent_id=agent_id,
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

        self._seq += 1
        self._last_hash = event.this_hash
        return event


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    error: str | None = None


def verify_log(path: str | Path, public_key: Ed25519PublicKey) -> VerifyResult:
    """Recompute the chain and check every signature. Detects any tampering."""
    events: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    prev = GENESIS_HASH
    for i, ev in enumerate(events):
        # 1. sequence is contiguous
        if ev["seq"] != i:
            return VerifyResult(False, i, f"seq gap at index {i}: got {ev['seq']}")
        # 2. chain link matches
        if ev["prev_hash"] != prev:
            return VerifyResult(False, i, f"broken chain at seq {ev['seq']}")
        # 3. recomputed content hash matches what was stored
        body = {k: v for k, v in ev.items() if k not in ("this_hash", "signature")}
        recomputed = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        if recomputed != ev["this_hash"]:
            return VerifyResult(False, i, f"content tampered at seq {ev['seq']}")
        # 4. signature is valid for this hash
        try:
            public_key.verify(bytes.fromhex(ev["signature"]), bytes.fromhex(ev["this_hash"]))
        except InvalidSignature:
            return VerifyResult(False, i, f"bad signature at seq {ev['seq']}")
        prev = ev["this_hash"]

    return VerifyResult(True, len(events))
