# Detections as code

Microsoft Sentinel / KQL detection rules, version-controlled and validated in CI.

Each `*.yml` file is one detection: a KQL query plus metadata (severity, MITRE
ATT&CK mapping, data source, false positives, references). `validate.py` loads and
checks every rule, and `tests/test_detections.py` runs that check in the pipeline —
so a malformed or unmapped detection can never merge.

| Detection | Severity | MITRE | Source |
|---|---|---|---|
| Password spray | high | T1110.003 | SigninLogs |
| New Global Administrator | high | T1098 | AuditLogs |
| Legacy-auth sign-in | medium | T1078 | SigninLogs |

## What runs where

- **Implemented here:** the rule files, the Python validator, and the CI gate
  (metadata correctness, MITRE mapping, data-source and query sanity).
- **External (not run here):** the KQL executes inside **Microsoft Sentinel**
  against real log tables. No Azure or live data is required to validate the rules.

## Run the validator locally

```bash
python detections/validate.py     # prints each rule's id / severity / technique / source
python -m pytest -q               # the CI gate, run locally
```
