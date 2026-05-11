# Sysmon Configuration

## Overview

This folder contains the Sysmon configuration used within the Windows SOC Detection Lab.

Sysmon was deployed to improve Windows endpoint telemetry visibility and provide detailed logging for detection engineering and threat hunting within Microsoft Sentinel.

---

# Sysmon Version

Sysmon was downloaded from Microsoft Sysinternals:

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

# Configuration Used

This project uses the SwiftOnSecurity Sysmon configuration:

https://github.com/SwiftOnSecurity/sysmon-config

The configuration helps:

- Reduce unnecessary logging noise
- Improve detection quality
- Focus on security-relevant events
- Enhance SOC visibility

---

# Installation Command

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

---

# Important Sysmon Event IDs

| Event ID | Description           |
| -------- | --------------------- |
| 1        | Process Creation      |
| 3        | Network Connection    |
| 7        | Image Loaded          |
| 11       | File Creation         |
| 13       | Registry Modification |
| 22       | DNS Query             |

---

# Why Sysmon Matters

Default Windows logging often lacks detailed endpoint visibility required for modern SOC operations.

Sysmon provides enhanced telemetry for:

- Process execution monitoring
- PowerShell activity
- Suspicious command-line detection
- Persistence mechanisms
- Network activity
- Threat hunting

This telemetry is critical for:

- Detection engineering
- Incident investigation
- Behavioral analysis
- Threat hunting workflows

---

# Telemetry Pipeline

Windows 11 VM  
↓  
Sysmon  
↓  
Windows Event Logs  
↓  
Azure Monitor Agent  
↓  
Log Analytics Workspace  
↓  
Microsoft Sentinel

---

# Files Included

## sysmonconfig-export.xml

Primary Sysmon configuration file used for telemetry collection.

---

# Skills Demonstrated

- Windows Endpoint Monitoring
- Sysmon Configuration
- Telemetry Engineering
- Microsoft Sentinel Integration
- Event Log Analysis
- Detection Engineering
