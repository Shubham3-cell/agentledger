# Infrastructure (Terraform) — hardened reference

Secure-by-default Azure infrastructure for AgentLedger's SOC layer, authored as
Infrastructure-as-Code and scanned by **Checkov** in CI on every push.

| Resource | Hardening |
|---|---|
| Storage Account | TLS 1.2, HTTPS-only, public access disabled, network default-deny, shared-key disabled, infrastructure encryption, soft-delete + versioning |
| Key Vault | RBAC authorization, purge protection, soft-delete, public access disabled, network default-deny |
| Managed Identity | user-assigned — replaces client secrets (no secret to leak) |
| Network Security Group | explicit deny-all inbound (no internet SSH/RDP) |
| Azure Policy | assignment enforcing storage network restrictions |

## What runs where

- **Implemented here:** the Terraform, hardened by design, and a Checkov scan that
  **fails the build** on misconfiguration (see `.checkov.yaml`).
- **NOT run here:** `terraform apply`. This is a scanned reference baseline — it is
  never deployed, so it incurs **no Azure cost**. Deploying it (optional) would use
  OIDC + the managed identity and a secure remote state backend.

## Scan it locally

```bash
pip install checkov
checkov -d infra
```
