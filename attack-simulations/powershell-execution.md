# PowerShell Execution Simulation

## Overview

This attack simulation demonstrates PowerShell execution activity within the Windows SOC Detection Lab environment.

The objective was to generate realistic PowerShell telemetry and validate Sysmon visibility and Microsoft Sentinel detection capabilities.

---

# Simulation Objective

The purpose of this simulation was to:
- Generate PowerShell execution telemetry
- Validate Sysmon Event ID 1 logging
- Detect PowerShell activity using KQL
- Practice basic threat hunting workflows

---

# Commands Executed

The following commands were executed inside the Windows 11 VM:

```powershell
whoami
Get-Process
```

These commands generated PowerShell-related process execution telemetry collected by Sysmon and forwarded into Microsoft Sentinel.

---

# Telemetry Source

The simulation relied on:

- Sysmon Event ID 1 (Process Creation)
- Microsoft Sentinel
- Azure Monitor Agent
- KQL Queries

---

# Detection Query

The following KQL query was used to detect PowerShell execution activity:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| sort by TimeGenerated desc
```

---

# PowerShell Execution Activity

![PowerShell Execution](../screenshots/powershell-execution.png)

---

# Detection Results

Microsoft Sentinel successfully detected PowerShell-related activity generated from the Windows VM.

The telemetry included:
- powershell.exe execution
- spawned child processes
- command execution activity
- endpoint hostname information
- timestamps

---

# MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |

---

# Skills Demonstrated

- PowerShell Monitoring
- Sysmon Telemetry Analysis
- Microsoft Sentinel
- KQL Querying
- Detection Engineering
- Threat Hunting
