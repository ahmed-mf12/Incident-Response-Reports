# Incident Report IR-2026-002: LSASS Memory Access - Suspected Credential Dumping

## Incident Summary

| Field | Details |
|---|---|
| **Incident ID** | IR-2026-002 |
| **Date Detected** | 2026-08-22 |
| **Severity** | Critical |
| **Status** | Closed - Contained |
| **Analyst** | Ahmed Mahmoud |
| **Detection Source** | [LSASS Credential Dumping Sigma Rule](https://github.com/ahmed-mf12/SOC-Detection-Rules/blob/main/sigma-rules/lsass-credential-dumping.yml) |

## Initial Alert

SIEM alert triggered based on the `Suspicious Access to LSASS Memory` detection rule, flagging a process (`procdump.exe`) requesting a high-privilege access handle to `lsass.exe` on host `HOST-WKS-027`, a known technique for dumping credentials from memory.

## Investigation

1. Reviewed Sysmon Event ID 10 (Process Access) logs on `HOST-WKS-027` for the specific `GrantedAccess` value flagged by the rule.
2. Identified the requesting process as `procdump.exe`, launched from a non-standard directory (`C:\Users\Public\`) rather than an approved administrative tools path.
3. Reviewed parent process chain to determine how `procdump.exe` was launched, tracing it back to a suspicious PowerShell process.
4. Checked for any dumped output files (`.dmp`) created around the same timestamp on disk.
5. Confirmed the user account associated with the session was not an authorized security or IT administrator.

## Timeline

| Time (UTC) | Event |
|---|---|
| 09:14 | Suspicious PowerShell process spawned |
| 09:15 | procdump.exe executed, targeting lsass.exe |
| 09:15 | SIEM alert triggered |
| 09:20 | Analyst began investigation |
| 09:35 | Host isolated from network |
| 10:05 | Dump file identified and removed |
| 10:30 | Affected account disabled and credentials reset |

## Evidence

- Sysmon Event ID 10 (Process Access) showing `procdump.exe` accessing `lsass.exe` with a high-privilege access mask
- Sysmon Event ID 1 (Process Creation) showing the parent PowerShell process
- Discovery of a `.dmp` file in `C:\Users\Public\` matching the incident timestamp

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Affected Host | HOST-WKS-027 |
| Suspicious Process | procdump.exe |
| Dump File Location | C:\Users\Public\ |
| Access Target | lsass.exe |

## MITRE ATT&CK Mapping

- **T1003.001** - OS Credential Dumping: LSASS Memory
- **T1059.001** - PowerShell (parent process)

## Root Cause

An attacker gained initial access to `HOST-WKS-027` (root vector under further review) and used a legitimate Sysinternals tool (`procdump.exe`) — not natively malicious, but commonly abused — to dump LSASS memory in an attempt to harvest credentials for further lateral movement.

## Containment

- Immediately isolated `HOST-WKS-027` from the network
- Removed the generated `.dmp` file to prevent exfiltration

## Eradication

- Removed `procdump.exe` from the non-standard location
- Reset credentials for all accounts with recent interactive sessions on the host
- Verified no additional persistence mechanisms were present

## Recovery

- Reimaged the affected host as a precaution given the severity of the technique
- Reconnected to the network only after validation

## Recommendations

- Implement application control (e.g., AppLocker/WDAC) to restrict execution of tools like procdump.exe from non-administrative paths
- Enable LSASS Protected Process Light (PPL) or Credential Guard where supported
- Alert on any process requesting high-privilege access handles to lsass.exe
- Review and restrict local administrator group membership across endpoints
