# Incident Report IR-2026-001: Suspected Lateral Movement via PsExec

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-001 |
| **Date Detected** | 2026-08-20 |
| **Severity** | High |
| **Status** | Closed - Contained |
| **Analyst** | Ahmed Mahmoud |
| **Detection Source** | [PsExec Lateral Movement Sigma Rule](https://github.com/ahmed-mf12/SOC-Detection-Rules/blob/main/sigma-rules/psexec-lateral-movement.yml) |

## Initial Alert

A SIEM alert triggered based on the `PsExec Lateral Movement` detection rule, flagging the creation of a `PSEXESVC` service on a workstation (`HOST-WKS-014`), indicating a remote command execution attempt via PsExec.

## Investigation

1. Reviewed Windows Security and Sysmon logs on `HOST-WKS-014` around the alert timestamp.
2. Identified the source host initiating the PsExec connection: `HOST-SRV-002`.
3. Correlated authentication logs (Event ID 4624/4625) to confirm the account used and validate whether the logon was expected.
4. Checked whether `HOST-SRV-002` had any prior indicators of compromise (e.g., suspicious process execution, unusual outbound connections).
5. Confirmed the account used was a standard user account, not an IT admin account authorized for PsExec use — raising suspicion of credential misuse.

## Timeline

| Time (UTC) | Event |
|---|---|
| 14:02 | PSEXESVC service created on HOST-WKS-014 |
| 14:03 | Remote command execution observed via PsExec |
| 14:05 | SIEM alert triggered |
| 14:12 | Analyst began investigation |
| 14:40 | Source host isolated from network |
| 15:10 | Compromised account credentials reset |

## Evidence

- Windows Event ID 7045 (Service Installation) on HOST-WKS-014, showing PSEXESVC creation
- Windows Event ID 4624 (Successful Logon) correlating the source account and host
- Sysmon Event ID 1 (Process Creation) showing PsExec.exe execution from HOST-SRV-002

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Source Host | HOST-SRV-002 |
| Target Host | HOST-WKS-014 |
| Service Name | PSEXESVC |
| Account Used | (standard user account, not IT admin) |

## MITRE ATT&CK Mapping

- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1570** - Lateral Tool Transfer

## Root Cause

The standard user account had excessive local administrative privileges on `HOST-SRV-002`, which allowed the account (once compromised, likely via credential reuse) to be used for lateral movement via PsExec.

## Containment

- Isolated `HOST-SRV-002` and `HOST-WKS-014` from the network pending further analysis
- Disabled the compromised user account temporarily

## Eradication

- Reset credentials for the affected account
- Removed excessive local admin privileges from the account
- Verified no persistence mechanisms (scheduled tasks, services) were left on either host

## Recovery

- Reconnected both hosts to the network after validation
- Monitored both hosts for 72 hours post-incident for recurrence

## Recommendations

- Enforce the principle of least privilege for standard user accounts
- Restrict PsExec and similar remote execution tools to authorized IT administrator accounts only
- Implement alerting on any PSEXESVC service creation outside of approved maintenance windows
- Conduct periodic account privilege audits across the environment
