# SIEM Lab Notes

## Overview
Hands-on SIEM and detection engineering lab using Elastic Stack, focused on developing and validating detection logic across endpoint and network telemetry.

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

***

## Additional Lab: Network-Based Detection (Raspberry Pi)

### Overview
Built a lightweight network monitoring and alerting solution using a Raspberry Pi to simulate a basic network detection sensor capable of identifying changes in asset presence and generating real-time alerts. The goal was to detect new devices joining the local network and generate real-time alerts, similar to how SOC environments monitor network activity.

---

### Objectives
- Gain hands-on experience with network discovery and asset enumeration
- Build detection logic to identify new or unauthorized devices
- Implement basic alerting using SMTP (email notifications)
- Understand alert noise and the need for tuning

---

### Tools & Technologies
- Raspberry Pi 5 (Ubuntu/Debian-based OS)
- `arp-scan` (network discovery)
- Bash scripting
- `msmtp` / SMTP (email alerting)

---

### Implementation

#### 1. Network Discovery
Used `arp-scan` to enumerate devices on the local network:
```bash
sudo arp-scan --localnet
```

#### 2. Baseline Creation
Captured an initial snapshot of known devices:
```bash
./detect.sh   # first run creates baseline.txt
```

#### 3. Detection Logic
Compared current scan results to baseline using diff logic:
- New devices identified by IP/MAC comparison
- Utilized `comm` and sorting to isolate new entries

#### 4. Alerting
Integrated SMTP email alerts using `msmtp`:
- Configured Gmail SMTP with app password
- Triggered alerts when new devices were detected

Example alert:
```
🚨 New device detected:

10.0.0.X    9a:f3:XX:XX:XX:XX    Unknown device (locally administered MAC)
```

---

### Detection Script

```bash
#!/bin/bash

BASELINE="baseline.txt"
CURRENT="current.txt"

# Run scan (clean output)
sudo arp-scan --localnet 2>/dev/null | grep -E "^[0-9]" > $CURRENT

# Create baseline if it doesn't exist
if [ ! -f "$BASELINE" ]; then
    cp $CURRENT $BASELINE
    echo "Baseline created."
    exit 0
fi

# Find NEW devices
NEW=$(comm -13 <(sort $BASELINE) <(sort $CURRENT))

if [ -n "$NEW" ]; then
    echo "🚨 NEW DEVICE DETECTED!"
    echo "$NEW"

    echo -e "🚨 New device detected:\n\n$NEW" | mail -s "Network Alert 🚨" your-email@gmail.com

    # Update baseline
    cp $CURRENT $BASELINE
fi
```

---

### Key Takeaways
- Built a simple detection pipeline: **data collection → analysis → alerting**
- Learned how network devices can use randomized MAC addresses (locally administered MACs)
- Identified challenges with alert noise and need for filtering/tuning
- Gained practical understanding of how SOC tools detect and alert on network changes
- Recognized the need for alert tuning to reduce noise from legitimate devices (e.g., MAC randomization)

---

### Future Improvements
- Filter known devices to reduce alert noise
- Add device labeling (known assets vs unknown)
- Send logs to Elastic for centralized analysis
- Replace polling with event-driven monitoring (if applicable)

## Impact

This lab demonstrates the ability to build detection pipelines beyond endpoint logs, incorporating network-level visibility and custom alerting mechanisms.
