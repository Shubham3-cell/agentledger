# 🛡️ AgentLedger — a security, policy & evidence layer for AI agents

![Status](https://img.shields.io/badge/Status-MVP%20in%20progress-2563eb)
![Language](https://img.shields.io/badge/Python-3.11%2B-3572A5)
![Security](https://img.shields.io/badge/Focus-AI%20Agent%20%2F%20MCP%20Security-6941C6)
![Evidence](https://img.shields.io/badge/Audit-Hash%20chain%20%2B%20Ed25519-1a7a48)
![License](https://img.shields.io/badge/License-MIT-9a6a12)

> AI agents are being handed real tools — files, mailboxes, cloud APIs, incident systems. **MCP is the plumbing that connects them; AgentLedger is the security, policy and evidence layer around it.** Every agent gets an identity, every action passes a policy, every consequential action needs approval, and every execution leaves a tamper-evident record.

---

## The idea in one line

**Every agent an identity. Every action a policy. Every workflow an intent. Every consequential action an approval path. Every execution a tamper-evident record.**

An agent should not be able to call a tool just because it can reach the server. It should call a tool only when a **deterministic policy** allows it, only after a **human approves** anything destructive, and never without leaving a **signed, hash-chained** record of what happened and why.

---

## What's built (Sprints 1–2)

The full boundary runs end to end, across two fake MCP servers so the security layer can be shown without external dependencies. The caller presents a **token** — never a claimed identity — and every gate is enforced in order:

```
authenticate -> resolve tool -> scope check -> policy -> (execute | hold | block) -> audit event
```

| Component | What it does | File |
|---|---|---|
| **Agent identity** | Every actor has a stable id + roles | `agents/identity.py` |
| **Auth service** | Issues **scoped, hashed, expiring** credentials; verifies tokens; **revokes** | `gateway/auth.py` |
| **Tool registry** | Declares each tool's **server** + **required scope**; routes across servers | `gateway/registry.py` |
| **MCP Gateway** | The single boundary: authn → scope → policy → execute → audit | `gateway/gateway.py` |
| **Policy engine** | Deterministic **ALLOW / DENY / APPROVAL**, **default deny** | `policy/engine.py` |
| **Tamper-evident audit** | SHA-256 **hash chain** + **Ed25519** signatures | `audit/log.py` |
| **Fake MCP servers** | Files + mail — two backends to route between | `mcp_servers/` |

**Sprint 2 closed Sprint 1's trust hole:** the gateway no longer accepts an Agent the caller *claims* to be. The caller proves identity with a token; the gateway derives the agent from it, enforces the credential's scopes (least privilege, before policy runs), and audits every attempt — including rejected ones — against the identity actually proven.

---

## Run it

```bash
pip install -r requirements.txt
python demo.py
```

You'll see an in-scope call execute, a destructive call held for approval, an **out-of-scope** call blocked before policy, an **unauthenticated** token rejected, a **revoked** credential stop working — then the audit log **verify clean**, and finally a deliberate tamper that verification **catches**.

```bash
pip install pytest && pytest -q      # the guarantees as tests
```

---

## Why each design choice

- **Default deny.** If no role explicitly permits a tool, the answer is DENY. Least privilege is the default, not an add-on.
- **Approval for destructive actions.** `delete_file` is never refused outright *or* run silently — it's **held for a human**. Consequence, not step count, decides what escalates.
- **Hash chain.** Each event stores the previous event's hash, so editing or deleting any earlier event breaks every hash after it. Tampering is *detectable*.
- **Ed25519 signatures.** Even a full chain recompute can't forge an event without the signing key; verification needs only the public key.
- **Deterministic decisions.** Same input, same verdict — which is what makes the audit trail explainable after the fact.

---

## Roadmap

- **S1 · Foundations** ✅ — repo, gateway, policy, tamper-evident audit
- **S2 · Gateway & identity** ✅ — token auth, tool registry, scoped credentials, revocation *(this)*
- **S3 · Policy & intent** — intent scoping, per-parameter conditions
- **S4 · Evidence** — OpenTelemetry trace/run/agent IDs, chain head anchored in Azure Blob **WORM**, signing key in **Key Vault**
- **S5 · Approval & dashboard** — human-in-the-loop service + console
- **S6 · Killer demo** *(stretch)* — real Entra / Defender / Intune MCP tools: *"Investigate Defender incident 12345"* end-to-end
- **S7 · Harden & ship** — red-team, Definition of Done, landing page

---

## Threats this addresses

Excessive agency · confused-deputy · prompt-injection-driven tool abuse · tool poisoning · repudiation. The policy engine constrains *what* an agent can do; the audit layer proves *what it did*.

> Built in public as part of a hands-on cloud-security portfolio. MVP uses synthetic data and a fake MCP server; no production systems involved.
