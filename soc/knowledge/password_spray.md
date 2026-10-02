# Password Spray Response Runbook

MITRE: T1110.003 (Password Spraying) — Credential Access.

## Indicators
A single source IP failing authentication against many distinct accounts in a
short window.

## Response steps
1. Confirm the source IP and affected accounts in Sentinel SigninLogs.
2. Block the source IP via a Conditional Access named location.
3. Force a password reset for any account that succeeded after the spray.
4. Verify or enforce MFA on all targeted accounts.
5. Isolate any endpoint showing a successful sign-in from the spray IP.
