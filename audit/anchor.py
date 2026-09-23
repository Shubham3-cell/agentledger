"""WORM anchor — an external, immutable witness of the chain head.

A hash chain proves the log wasn't edited *in the middle*: change any past event
and every later hash breaks. But it can't, on its own, catch **truncation** — an
attacker who deletes the last N events leaves a shorter chain that is still
internally consistent and still verifies. There's nothing left in the log to say
those events ever existed.

The fix is an external witness. After each event, the chain head (its hash and
sequence number) is written to a separate append-only store. To hide a
truncation an attacker would now have to rewrite this store too — and it lives
somewhere they can't.

- **MVP:** a local append-only file (this class).
- **Production:** an Azure Blob container with an **immutability (WORM) policy**,
  so the anchor is write-once even to an admin. The audit log and the anchor sit
  in different trust domains; compromising one doesn't compromise the other.

Verification compares the log's current head to the latest anchor: if the anchor
knows about a sequence number the log no longer contains, the log was truncated.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AnchorRecord:
    seq: int
    head_hash: str
    timestamp: float


class WormAnchor:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def anchor(self, seq: int, head_hash: str) -> None:
        """Record the current chain head. Append-only — never rewrites history."""
        rec = {"seq": seq, "head_hash": head_hash, "timestamp": time.time()}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    def latest(self) -> AnchorRecord | None:
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last is None:
            return None
        return AnchorRecord(last["seq"], last["head_hash"], last["timestamp"])
