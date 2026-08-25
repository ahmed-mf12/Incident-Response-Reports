# Incident-Response-Reports

Documented incident response reports covering alert triage, investigation, containment, and remediation, based on scenarios linked to my detection engineering work.

## Purpose

These reports simulate realistic SOC investigations, applying the detection rules I've built in [SOC-Detection-Rules](https://github.com/ahmed-mf12/SOC-Detection-Rules) to structured incident documentation — the kind of end-to-end workflow expected of a SOC Analyst.

## Reports

| ID | Title | Severity | MITRE ATT&CK |
|---|---|---|---|
| [IR-2026-001](reports/IR-2026-001-psexec-lateral-movement.md) | Suspected Lateral Movement via PsExec | High | T1021.002, T1570 |
| [IR-2026-002](reports/IR-2026-002-lsass-credential-dumping.md) | LSASS Memory Access - Suspected Credential Dumping | Critical | T1003.001, T1059.001 |

## Report Structure

Each report follows a consistent structure:
- Incident Summary
- Initial Alert
- Investigation
- Timeline
- Evidence
- Indicators of Compromise (IOCs)
- MITRE ATT&CK Mapping
- Root Cause
- Containment / Eradication / Recovery
- Recommendations

## Status

Actively growing collection, developed alongside my Blue Team / SOC Analyst training and detection engineering work.
