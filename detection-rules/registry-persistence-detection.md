
# Registry Persistence Detection

## Overview

This detection rule identifies Windows Registry Run Key persistence activity using Sysmon registry modification telemetry collected in Microsoft Sentinel.

Registry Run Keys are commonly abused by attackers to:
- Maintain persistence after reboot
- Automatically execute malware
- Re-establish access
- Launch malicious payloads during user logon

The objective of this detection was to identify suspicious registry persistence behavior using KQL and Sysmon Event ID 13 telemetry.

---

# Detection Logic

The detection hunts for:
- Registry Run Key modifications
- Persistence-related registry paths
- Suspicious startup entries

The following telemetry fields were important during analysis:
- TargetObject
- Details
- Image
- User
- Registry Path

---

# Initial Detection Query

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| sort by TimeGenerated desc
```

---

# Problem Identified

The initial query generated excessive noise because Windows continuously performs legitimate registry operations.

This demonstrated an important SOC concept:

Raw telemetry often requires tuning before becoming operationally useful.

---

# Tuned Detection Query

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| where RenderedDescription has "CurrentVersion\\Run"
| sort by TimeGenerated desc
```

---

# Detection Screenshot

![Registry Persistence Detection](../screenshots/registry-persistence-detection.png)

---

# Detection Results

Microsoft Sentinel successfully detected registry persistence activity generated from the Windows VM.

The detection identified:
- Registry Run Key creation
- Persistence value modifications
- Updater registry value creation
- notepad.exe startup persistence
- Registry modification telemetry
- User context information

---

# Telemetry Analysis

The investigation confirmed that Sysmon Event ID 13 captured:
- Registry value modifications
- Registry persistence paths
- Process metadata
- Persistence-related registry changes

The telemetry was successfully forwarded into Microsoft Sentinel using:
- Azure Monitor Agent
- Azure Arc
- Data Collection Rules

---

# Why This Detection Matters

Registry persistence is frequently associated with:
- Malware persistence
- RAT deployment
- Credential stealers
- Post-exploitation activity
- Long-term attacker access

Attackers commonly abuse:
```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

to automatically launch payloads during user logon.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1547.001 | Registry Run Keys / Startup Folder |

---

# Skills Demonstrated

- Detection Engineering
- Registry Monitoring
- Persistence Detection
- Threat Hunting
- Microsoft Sentinel
- Sysmon Analysis
- KQL Querying
- Behavioral Detection
