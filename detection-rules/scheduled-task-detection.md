# Scheduled Task Persistence Detection

## Overview

This detection rule identifies scheduled task persistence activity using Sysmon process creation telemetry collected in Microsoft Sentinel.

Scheduled tasks are commonly abused by attackers to:
- Maintain persistence after reboot
- Automatically execute payloads
- Launch malware silently
- Re-establish access during user logon

The objective of this detection was to identify suspicious scheduled task creation activity using KQL and Sysmon Event ID 1 telemetry.

---

# Detection Logic

The detection hunts for:
- `schtasks.exe` execution
- Scheduled task creation commands
- Persistence-related task configuration
- Suspicious startup task behavior

The following telemetry fields were important during analysis:
- Image
- CommandLine
- ParentImage
- User
- Task Name

---

# KQL Detection Query

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "schtasks"
| sort by TimeGenerated desc
```

---

# Detection Screenshot

![Scheduled Task Detection](../screenshots/scheduled-task-detection.png)

---

# Detection Results

Microsoft Sentinel successfully detected scheduled task persistence activity generated from the Windows VM.

The detection identified:
- schtasks.exe execution
- scheduled task creation activity
- UpdaterTask persistence creation
- onlogon trigger configuration
- notepad.exe payload execution
- process creation telemetry
- parent-child process relationships

---

# Telemetry Analysis

The investigation confirmed that Sysmon Event ID 1 captured:
- schtasks.exe process execution
- full command-line visibility
- scheduled task configuration parameters
- parent process details
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

launched:

```text
schtasks.exe
```

This parent-child process relationship is important because PowerShell-driven persistence activity is frequently associated with:
- post-exploitation behavior
- malware execution
- persistence establishment
- attacker automation

The command-line telemetry also exposed:
- `/create`
- `/sc onlogon`
- `UpdaterTask`
- `notepad.exe`

which clearly identified persistence creation behavior.

---

# Why This Detection Matters

Scheduled tasks are frequently abused by:
- Malware operators
- Ransomware groups
- Red teams
- Persistence frameworks
- Threat actors

Attackers commonly leverage scheduled tasks because:
- built into Windows
- reliable persistence mechanism
- blends into normal administrative activity
- supports automation

---

# MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1053.005 | Scheduled Task |

---

# Skills Demonstrated

- Detection Engineering
- Threat Hunting
- Scheduled Task Monitoring
- Sysmon Analysis
- Microsoft Sentinel
- KQL Querying
- Behavioral Detection
