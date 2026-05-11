# Windows SOC Detection Lab Architecture

## Overview

This project simulates a Windows-based SOC monitoring environment using Sysmon and Microsoft Sentinel for centralized logging, detection engineering, and threat hunting.

The lab was designed to replicate real-world enterprise telemetry pipelines used in Security Operations Centers (SOCs).

---

# Architecture Flow

Windows 11 VM  
↓  
Sysmon  
↓  
Windows Event Logs  
↓  
Azure Monitor Agent (AMA)  
↓  
Azure Arc  
↓  
Data Collection Rule (DCR)  
↓  
Log Analytics Workspace  
↓  
Microsoft Sentinel

---

# Components

## Windows 11 Virtual Machine

The Windows 11 VM acts as the monitored endpoint within the SOC lab environment.

The VM is used for:

- Endpoint monitoring
- Telemetry generation
- Attack simulation
- Detection validation

---

## Sysmon

Sysmon was installed using the SwiftOnSecurity configuration to provide enhanced Windows telemetry visibility.

Sysmon generates logs for:

- Process creation
- Network connections
- File creation
- Registry modifications
- PowerShell execution
- DNS activity

Important Sysmon Event IDs:

- Event ID 1 → Process Creation
- Event ID 3 → Network Connection
- Event ID 11 → File Creation
- Event ID 13 → Registry Modification
- Event ID 22 → DNS Query

---

## Azure Arc

Azure Arc was used to onboard the local Windows VM into Azure.

This allowed:

- Cloud-based monitoring
- Agent management
- DCR association
- Sentinel integration

---

## Azure Monitor Agent (AMA)

The Azure Monitor Agent collects Windows Event Logs from the endpoint and forwards telemetry into the Log Analytics Workspace.

Collected logs include:

- Sysmon Operational Logs
- Security Logs

---

## Data Collection Rule (DCR)

The DCR defines:

- Which logs are collected
- Which machines send telemetry
- Destination workspace configuration

Configured log channels:

- Microsoft-Windows-Sysmon/Operational
- Security

---

## Log Analytics Workspace

The Log Analytics Workspace stores centralized telemetry collected from the Windows endpoint.

This workspace acts as the backend data source for Microsoft Sentinel.

---

## Microsoft Sentinel

Microsoft Sentinel provides:

- Centralized log visibility
- KQL querying
- Detection engineering
- Threat hunting
- Incident analysis

Telemetry was validated using KQL queries against Sysmon Event ID 1 process creation logs.

---

# Telemetry Validation

The following KQL query was used to validate successful ingestion:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| sort by TimeGenerated desc
```

---

# Skills Demonstrated

- Windows Security Monitoring
- SIEM Deployment
- Microsoft Sentinel
- Azure Arc Integration
- Sysmon Configuration
- KQL Querying
- Detection Engineering
- Log Ingestion Validation
- SOC Architecture Design

---
