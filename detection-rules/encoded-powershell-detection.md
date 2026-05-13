# Encoded PowerShell Detection

## Overview

This detection rule identifies Base64-encoded PowerShell execution activity using Sysmon process creation telemetry collected in Microsoft Sentinel.

Encoded PowerShell commands are commonly abused by attackers to:
- Obfuscate malicious activity
- Hide command execution
- Bypass simple detections
- Execute payloads stealthily

The objective of this detection was to identify suspicious PowerShell execution patterns using KQL and Sysmon Event ID 1 logs.

---

# Detection Logic

The detection hunts for:
- `-enc`
- `-EncodedCommand`

within Sysmon process creation logs.

The following telemetry fields were important during analysis:
- Process Image
- CommandLine
- ParentImage
- User
- Timestamp

---

# KQL Detection Query

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("-enc","EncodedCommand")
| sort by TimeGenerated desc
```

---

# Detection Screenshot

![Encoded PowerShell Detection](../screenshots/encoded-powershell-detection.png)

---

# Detection Results

Microsoft Sentinel successfully detected encoded PowerShell execution activity generated from the Windows VM.

The detection identified:
- powershell.exe execution
- encoded command-line arguments
- Base64 payload execution
- process creation telemetry
- parent-child process relationships
- endpoint hostname information

---

# Telemetry Analysis

The investigation confirmed that Sysmon Event ID 1 captured:
- Full PowerShell command-line execution
- Encoded payload visibility
- Parent process details
- Process execution metadata

The telemetry was successfully forwarded into Microsoft Sentinel using:
- Azure Monitor Agent
- Azure Arc
- Data Collection Rules

---

# Why This Detection Matters

Encoded PowerShell execution is frequently associated with:
- Malware loaders
- Initial access payloads
- Post-exploitation frameworks
- Red team activity
- Obfuscated scripting techniques

While encoded PowerShell is not always malicious, it represents suspicious behavior that should be investigated further during SOC operations.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |
| T1027 | Obfuscated/Encoded Files and Information |

---

# Skills Demonstrated

- Detection Engineering
- Threat Hunting
- KQL Querying
- Microsoft Sentinel
- Sysmon Analysis
- PowerShell Monitoring
- Behavioral Detection
