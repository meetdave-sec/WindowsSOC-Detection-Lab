# Reconnaissance Activity Detection

## Overview

This detection rule identifies reconnaissance activity using Sysmon process creation telemetry collected in Microsoft Sentinel.

Reconnaissance commands are commonly executed by attackers after gaining initial access to a system in order to:
- identify user accounts
- enumerate processes
- discover network configuration
- identify host information
- prepare for lateral movement

The objective of this detection was to identify suspicious reconnaissance behavior using KQL and Sysmon Event ID 1 telemetry.

---

# Detection Logic

The detection hunts for:
- whoami.exe execution
- hostname.exe execution
- ipconfig.exe execution
- tasklist.exe execution
- net.exe execution

The following telemetry fields were important during analysis:
- Image
- CommandLine
- ParentImage
- User
- Process execution metadata

---

# KQL Detection Query

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("whoami.exe","hostname.exe","ipconfig.exe","tasklist.exe","net.exe")
| sort by TimeGenerated desc
```

---

# Detection Screenshot

![Reconnaissance Detection](../screenshots/reconnaissance-detection.png)

---

# Detection Results

Microsoft Sentinel successfully detected reconnaissance activity generated from the Windows VM.

The detection identified:
- whoami.exe execution
- hostname.exe execution
- ipconfig.exe execution
- tasklist.exe execution
- net.exe execution
- process creation telemetry
- PowerShell-spawned reconnaissance activity

---

# Telemetry Analysis

The investigation confirmed that Sysmon Event ID 1 captured:
- process execution telemetry
- full command-line visibility
- reconnaissance command activity
- parent-child process relationships
- user context information

The telemetry was successfully forwarded into Microsoft Sentinel using:
- Azure Monitor Agent
- Azure Arc
- Data Collection Rules

---

# Important Detection Findings

The telemetry revealed that:

```text
powershell.exe
```

spawned multiple reconnaissance-related processes including:
- whoami.exe
- ipconfig.exe
- tasklist.exe
- net.exe

This parent-child process relationship is important because PowerShell-driven discovery activity is frequently associated with:
- post-exploitation behavior
- attacker reconnaissance
- hands-on-keyboard activity
- environment enumeration

---

# Why This Detection Matters

Reconnaissance activity is a critical phase during intrusions because attackers require situational awareness before:
- privilege escalation
- lateral movement
- persistence establishment
- credential access

Behavioral chains involving multiple discovery commands executed sequentially may indicate malicious operator activity.

---

# Important SOC Concept

Individually, commands such as:
- whoami
- hostname
- ipconfig

may be legitimate administrative tools.

However, sequential execution of multiple reconnaissance commands from PowerShell may become operationally suspicious.

This demonstrates the importance of:
- behavioral analytics
- process correlation
- activity chaining
- contextual investigation

---

# MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1033 | System Owner/User Discovery |
| T1082 | System Information Discovery |
| T1016 | System Network Configuration Discovery |
| T1057 | Process Discovery |
| T1087 | Account Discovery |

---

# Skills Demonstrated

- Threat Hunting
- Reconnaissance Detection
- Process Monitoring
- Sysmon Analysis
- Microsoft Sentinel
- Behavioral Detection
- KQL Querying
- Process Correlation
