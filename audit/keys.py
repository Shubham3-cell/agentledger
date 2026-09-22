"""Signing key management for the audit log (MVP: on-disk PEM).

Sprint 4 replaces this with Azure Key Vault — the rest of the code only ever
touches the returned key objects, so that swap is local to this file.
"""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def load_or_create_keypair(
    priv_path: str | Path,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Load an Ed25519 private key from PEM, creating one on first run."""
    priv_path = Path(priv_path)
    if priv_path.exists():
        private = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        assert isinstance(private, Ed25519PrivateKey)
    else:
        private = Ed25519PrivateKey.generate()
        priv_path.parent.mkdir(parents=True, exist_ok=True)
        priv_path.write_bytes(
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return private, private.public_key()
