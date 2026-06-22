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
- Subnet: `192.168.200.0/24`
- Systems:
  - Windows 11 Endpoint
  - Ubuntu (Elastic / Kibana)
- Purpose:
  - Internal SIEM communication
  - Log ingestion and detection analysis

---

#### ✅ Home / External Network (Bridged)
- Subnet: `10.0.0.0/24`
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
  - `10.0.0.x`
  - Connected to Pi-hole for DNS monitoring

- Adapter 2:
  - `192.168.200.x`
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
- Field used:

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

Broad search:

```kql
event.dataset: "windows.powershell_operational"
and event.code: 4104
```

Refined detection:

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
- Remote content was retrieved and/or executed in memory
- Script Block Logging (4104) captured the full command

Example Log:

```text
Invoke-WebRequest http://example.com
```

***

### Detection Rule (Elastic)

```kql
event.code: "4104" AND powershell.file.script_block_text: ("*DownloadString*" OR "*Invoke-WebRequest*")
```

Rule Configuration:
- Name: download detection  
- Severity: Medium  
- Risk Score: 50  
- Interval: 1 minute  
- Lookback: 5 minutes  

***

### ✅ Validation

- Detection rule triggered successfully after executing test commands
- Alert contained:
  - correct host (`desktopwin11`)
  - correct user (`User1`)
  - correct script content

Example Alert Context:

```text
Invoke-WebRequest http://example.com
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
- Event ID 4688 captured the process creation
- The spawned process (`whoami.exe`) shows PowerShell as its parent

Example:

```text
process.name: whoami.exe
process.parent.name: powershell.exe
```

***

### ✅ Detection Query

```kql
event.code: "4688" and process.parent.name: "powershell.exe"
```

***

### ✅ Key Concept

- A child process is a process created by another process (parent)
- In this case:
  - PowerShell = parent process
  - whoami.exe = child process

- “PowerShell spawning a child process” means:
  PowerShell executed a command that launched another executable.

***

### ✅ Why This Matters

- Attackers often use PowerShell to launch additional tools or payloads
- Monitoring child processes helps detect:
  - command execution
  - lateral movement behavior
  - potential malware activity

***

### 🔹 PowerShell + DNS Correlation Detection (Multi-Source)

Test Command:

```text
powershell
Invoke-WebRequest http://example.com
```

***

### ✅ Observed Behavior

This test generated observable activity across multiple telemetry sources:

#### Endpoint (PowerShell Script Block Logging - 4104)

```text
Invoke-WebRequest http://example.com
```

#### Endpoint (Process Creation - 4688)

```text
process.parent.name: powershell.exe
```

#### Network (Pi-hole DNS Logging)

```text
10.0.0.89 → example.com
```

***

### ✅ Detection Approach

#### PowerShell Execution Detection (4104)

```kql
event.code: "4104" AND powershell.file.script_block_text: "*Invoke-WebRequest*"
```

#### PowerShell Process Activity (4688)

```kql
event.code: "4688" AND process.parent.name: "powershell.exe"
```

#### Network Visibility (Pi-hole)

```
http://10.0.0.214/admin
```

***

### ✅ Validation

- ✅ Script logged in Elastic (4104)
- ✅ Process activity recorded (4688)
- ✅ DNS logged in Pi-hole

***

### ✅ Key Concept: Multi-Source Correlation

| Activity | Data Source |
|--------|-----------|
| Command execution | PowerShell Script Block (4104) |
| Process behavior | Windows Security Log (4688) |
| Network request | DNS logs (Pi-hole) |

***

### ✅ Example Investigation Narrative

PowerShell was used to execute a web request (`Invoke-WebRequest`).  
The activity was confirmed via Script Block Logging (4104), supported by process creation logs (4688), and correlated with DNS activity observed in Pi-hole.

***

## Key Concepts Learned

### 🔹 Script Block Logging (Event ID 4104)

- Logs actual PowerShell code executed
- Captures commands after parsing and decoding

***

### 🔹 Command Line vs Execution Visibility

| Log Type | Purpose |
|--------|--------|
| Event 4688 | Shows how PowerShell was launched |
| Event 4104 | Shows what actually executed |

***

### 🔹 Obfuscation Insight

- Base64 encoding hides commands
- Script Block Logging reveals decoded content
- Detection should focus on behavior

***

## Detection Strategy Notes

- Start with broad queries before refining
- Validate detection logic using real logs
- Focus on behavioral patterns
- Correlate multiple data sources

***

## Key Learnings

- Script Block Logging is critical for detecting obfuscated activity  
- Detection requires tuning and validation  
- Single log sources are not enough  
- Correlating logs improves detection accuracy  
- Network + endpoint visibility provides stronger detections  

***

## Next Steps

- Detect encoded PowerShell using Event ID 4688
- Correlate command-line execution with script block logging
- Expand detections for additional techniques
- Integrate Pi-hole logs into Elastic for automated correlation
