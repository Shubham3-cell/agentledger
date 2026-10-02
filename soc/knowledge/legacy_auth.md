# Legacy Authentication Response Runbook

MITRE: T1078 (Valid Accounts). Legacy authentication protocols bypass MFA and most
Conditional Access policies.

## Response steps
1. Identify the account and legacy client app (IMAP, POP3, SMTP) in SigninLogs.
2. Block legacy authentication via Conditional Access.
3. Reset the account credential and require MFA re-registration.
4. Review mailbox rules and app consents for attacker persistence.
