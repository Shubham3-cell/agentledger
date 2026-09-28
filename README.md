# 🛡️ Entra ID Identity Hardening & Security Automation Lab

![Microsoft Entra ID](https://img.shields.io/badge/Microsoft-Entra%20ID-0078D4?logo=microsoftazure&logoColor=white)
![Conditional Access](https://img.shields.io/badge/Focus-Conditional%20Access-2563eb)
![Identity Protection](https://img.shields.io/badge/Identity-Protection%20%2B%20PIM-6941C6)
![PowerShell](https://img.shields.io/badge/Automation-PowerShell%20%2B%20Graph-012456?logo=powershell&logoColor=white)
![Licensing](https://img.shields.io/badge/Licensing-Entra%20ID%20P2-6941C6)
![Status](https://img.shields.io/badge/Status-Live-success)

> A hands-on lab that hardens a Microsoft Entra ID tenant against account-takeover attacks **and** automates the response — building a complete **mini-SOC loop: Detect → Triage → Contain.** Conditional Access, Identity Protection, PIM, PowerShell + Microsoft Graph automation, and an AI-assisted triage agent. Every control validated in report-only / What If before enabling.

---

## 📋 Overview

I built my own Entra ID tenant and configured a production-grade identity-security baseline, then layered on **automation and AI** to detect, triage, and contain threats end to end.

**The attacker's-eye view this defends against:** stolen password → blocked by MFA → attacker tries legacy auth to skip MFA → blocked → suspicious sign-in → challenged / flagged → leaked credential detected → account force-reset → an **impossible-travel** detection fires → an **AI agent triages** it into a ticket → a **PowerShell script revokes the sessions** and evicts the attacker.

---

## 🔁 The mini-SOC loop

| Stage | What does it | Built in |
|---|---|---|
| **Detect** | Identity Protection risk policies + a custom impossible-travel script | Days 4, 8 |
| **Triage** | AI SOC agent turns a raw event into a structured JSON incident ticket | Day 9 |
| **Contain** | PowerShell script revokes the compromised user's sessions | Day 7 |

---

## 🧱 Conditional Access baseline — at a glance

| Policy | Purpose | Trigger / Condition | Control | Excludes |
|---|---|---|---|---|
| **CA001** | Enforce MFA | All sign-ins | Require MFA | `CA-BreakGlass-Exclude` |
| **CA002** | Block legacy auth | Legacy client apps | Block access | `CA-BreakGlass-Exclude` |
| **CA003** | Risky sign-in defence | Sign-in risk = High | Require MFA | `CA-BreakGlass-Exclude` |
| **CA004** | Compromised-account defence | User risk = High | Require MFA + password change | `CA-BreakGlass-Exclude` |

*Naming convention: `CA + number + purpose + scope` — keeps the policy set auditable as it scales.*

---

## 🏗️ Lab environment

| Account | Role | Licence | Purpose |
|---|---|---|---|
| **LabAdmin** | Global Administrator | Entra ID P2 | Working admin |
| **Chris / Bala / Shahid** | *No admin rights* | Entra ID P2 | Standard test users (least privilege) |
| **bg-emergency01 / 02** | Global Administrator (permanent) | — | Break-glass emergency access |

Both break-glass accounts live in the security group **`CA-BreakGlass-Exclude`**, excluded from every policy.

---

# Part 1 — Identity Hardening (Conditional Access, Identity Protection, PIM)

## 🔐 Day 1 — Break-glass emergency accounts
Two cloud-only emergency admin accounts in an exclusion group.
> **Why:** emergency logins deliberately excluded from every policy, so a misconfiguration, MFA outage, or identity-provider failure can never lock the org out of its own tenant. Cloud-only, permanent admin, two for redundancy.

## 🔑 Day 2 — Enforce MFA — `CA001`
All users (excluding break-glass) → Require MFA. Built in **report-only**, validated in sign-in logs, then enabled. **Migrated the tenant off Security Defaults** to use granular Conditional Access.
> **Why:** MFA makes a stolen password useless alone — the top defence against account takeover.

## 🚫 Day 3 — Block legacy authentication — `CA002`
Condition scoped to legacy client apps only → **Block access**. Validated with the **What If** tool.
> **Why:** legacy protocols (POP/IMAP/SMTP) can't do MFA, so leaving them open lets attackers bypass MFA with a stolen password. Blocking them closes that back door.

## 🧠 Day 4 — Identity Protection risk policies — `CA003` & `CA004`
Adaptive, ML-driven policies:
- **Sign-in risk = High → require MFA** (is *this login* the real user?)
- **User risk = High → force password change** (is the *account* compromised? — e.g. leaked credentials). Enabled **SSPR** as the prerequisite.
> **Why:** MFA is static; Identity Protection is *adaptive* — it reacts to detected threats automatically.

## ⏱️ Day 5 — Privileged Identity Management (PIM)
Made a test user **eligible** (not active) for User Administrator, with **2-hour, MFA-and-justification-gated activation**.
> **Why:** eliminates *standing privilege* — admin rights exist only when activated, shrinking the attack window. Break-glass stays permanent as the deliberate exception.

---

# Part 2 — Security Automation (PowerShell + Microsoft Graph + AI)

## 💻 Day 6 — Microsoft Graph PowerShell — the automation gateway
Connected to Graph with **least-privilege scopes** (`User.Read.All`, `Group.Read.All`), then queried and filtered directory objects programmatically.
> **Why:** you can't click 5,000 users — Graph lets you read and act at scale. Delegated vs application permissions, and requesting only the scope the task needs.

## 🧯 Day 7 — Automated session revocation — `Revoke-Sessions.ps1`
Escalated to a **write scope** (`User.RevokeSessions.All`) and revoked a compromised user's sessions to force re-authentication.
> **Why:** a password reset alone doesn't kill live tokens — revoking sessions instantly evicts the attacker. This is the **Contain** step.

## 🧮 Day 8 — Impossible-travel detection — `Test-ImpossibleTravel.ps1`
A PowerShell script using the **haversine formula** to compute distance between two sign-in locations and derive implied travel speed — flagging physically impossible logins.
> **Why:** mirrors how Entra ID Protection detects atypical travel. Key insight: impossible travel is **distance ÷ time** — the same distance is impossible in 1 hour but plausible over 24. This is the **Detect** step.

## 🤖 Day 9 — AI SOC triage agent — `soc-triage-agent-prompt.txt`
An AI agent that ingests a raw security event and returns a **structured JSON incident ticket** — severity, MITRE ATT&CK mapping, indicators, and a recommended containment playbook.
> **Why:** automates Tier-1 triage so analysts focus on investigation. Structured JSON output is *machine-readable*, so it can feed a ticketing system or an automated playbook. This is the **Triage** step. See `example-triage-ticket.json`.

---

## 📁 Repository contents

```
entra-identity-hardening/
├── README.md
├── scripts/
│   ├── Revoke-Sessions.ps1          # Day 7 - containment
│   └── Test-ImpossibleTravel.ps1    # Day 8 - detection (haversine)
├── ai-agent/
│   ├── soc-triage-agent-prompt.txt  # Day 9 - agent design
│   └── example-triage-ticket.json   # Day 9 - sample output
└── screenshots/                     # policy + evidence screenshots
```

---

## 🎯 Key concepts demonstrated

- **Least privilege** — across users, PIM (just-in-time), break-glass exclusion, and Graph API scopes.
- **Safe change management** — report-only mode + the What If tool before enforcing.
- **Defence in depth** — MFA, legacy-auth blocking, risk-based policies layered together.
- **Security Defaults → Conditional Access migration** — blunt baseline to granular, testable control.
- **Automation at scale** — Microsoft Graph + PowerShell to read and act on the directory.
- **Threat containment** — session revocation vs password reset.
- **Detection logic** — impossible travel = distance ÷ time.
- **AI-assisted SOC** — structured, machine-readable triage that closes the loop.

---

## 🧰 Skills & technologies

`Microsoft Entra ID` · `Conditional Access` · `Entra ID Protection` · `Privileged Identity Management (PIM)` · `Multi-Factor Authentication` · `PowerShell` · `Microsoft Graph SDK` · `Identity & Access Management` · `Least Privilege` · `Incident Response` · `AI-assisted Security Operations` · `Defence in Depth`

---

## ✅ Outcome

A hardened Entra ID tenant with MFA enforced, legacy auth blocked, adaptive risk-based remediation, just-in-time privileged access, and protected break-glass access — **plus** an automated detect → triage → contain pipeline built with PowerShell, Microsoft Graph, and an AI triage agent. The standard secure identity baseline for a Microsoft organisation, extended into automation, and built and validated with professional rollout practices.

> *Part of an ongoing hands-on cloud security portfolio — building in public.*
