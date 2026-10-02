# Privileged Role Change Response Runbook

MITRE: T1098 (Account Manipulation). Watch for new Global Administrator grants.

## Response steps
1. Confirm who was added to which privileged role in AuditLogs.
2. Verify the change was approved (PIM activation or change ticket).
3. If unapproved, remove the role assignment and reset the actor's credentials.
4. Review the actor's recent sign-in and audit activity for further abuse.
