"""Authentication + scoped credentials.

The Sprint 1 gateway had a hole: the caller *handed in* an Agent object, so
anything could claim to be any agent. Sprint 2 closes it. The caller now
presents only a **token**; the gateway asks this service who that token belongs
to. Identity is proven, not asserted.

Each credential also carries **scopes** — the narrow set of capabilities that
identity is cleared for (e.g. `files:read`). This is least privilege at the
door: the scope check runs before the policy engine, so an agent can't even
*attempt* a tool outside its grant.

Security choices that matter here:
- Tokens are stored **hashed** (SHA-256), never in plaintext — a leaked store
  doesn't leak usable tokens.
- Credentials **expire**.
- Credentials can be **revoked** instantly.

MVP keeps the store in memory. Sprint 6 swaps issuance/verification for Entra
workload identity; the gateway only ever sees `authenticate() -> Agent`, so that
swap stays inside this file.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field

from agents.identity import Agent


class AuthError(Exception):
    """Raised when a token is missing, unknown, expired, or revoked."""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class Credential:
    agent: Agent
    scopes: frozenset[str]
    token_hash: str
    expires_at: float
    revoked: bool = False

    def is_valid(self, now: float) -> bool:
        return not self.revoked and now < self.expires_at


@dataclass
class Authenticated:
    """The result of a successful authentication: who, and what they may reach."""

    agent: Agent
    scopes: frozenset[str]


class AuthService:
    def __init__(self) -> None:
        # keyed by token hash so we never hold a usable token in memory
        self._creds: dict[str, Credential] = {}

    def issue(self, agent: Agent, scopes: list[str], ttl_seconds: int = 3600) -> str:
        """Mint a credential for an agent and return its (only) plaintext token."""
        token = f"al_{secrets.token_urlsafe(24)}"
        self._creds[_hash_token(token)] = Credential(
            agent=agent,
            scopes=frozenset(scopes),
            token_hash=_hash_token(token),
            expires_at=time.time() + ttl_seconds,
        )
        return token

    def authenticate(self, token: str | None) -> Authenticated:
        """Verify a presented token. Raises AuthError on any failure."""
        if not token:
            raise AuthError("no credential presented")
        cred = self._creds.get(_hash_token(token))
        if cred is None:
            raise AuthError("unknown credential")
        now = time.time()
        if cred.revoked:
            raise AuthError("credential revoked")
        if now >= cred.expires_at:
            raise AuthError("credential expired")
        return Authenticated(agent=cred.agent, scopes=cred.scopes)

    def revoke(self, token: str) -> None:
        cred = self._creds.get(_hash_token(token))
        if cred is not None:
            cred.revoked = True
