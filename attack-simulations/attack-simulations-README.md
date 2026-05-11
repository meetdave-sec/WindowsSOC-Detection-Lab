# Attack Simulations

## Overview

This folder contains controlled attack simulations performed within the Windows SOC Detection Lab environment.

The purpose of these simulations is to:
- Generate realistic Windows telemetry
- Validate Sysmon visibility
- Test Microsoft Sentinel detections
- Practice threat hunting workflows
- Improve detection engineering skills

All simulations are conducted in an isolated virtual lab environment.

---

# Attack Simulation Workflow

Each simulation includes:
- Objective
- Commands executed
- Telemetry generated
- Detection queries
- Microsoft Sentinel analysis
- MITRE ATT&CK mapping
- Screenshots

---

# Planned Simulations

## Encoded PowerShell Execution
Detection of Base64-encoded PowerShell commands using Sysmon Event ID 1 telemetry.

---

## PowerShell Reconnaissance Activity
Simulation of reconnaissance commands such as:
- whoami
- hostname
- ipconfig
- net user

---

## Registry Persistence Simulation
Detection of suspicious registry modifications commonly used for persistence.

---

## Suspicious Process Execution
Monitoring potentially suspicious Windows binaries and parent-child process relationships.

---

# Telemetry Sources

The following telemetry sources are used during attack simulations:
- Sysmon
- Windows Event Logs
- Microsoft Sentinel
- KQL Queries

---

# Skills Demonstrated

- Threat Hunting
- Detection Engineering
- Microsoft Sentinel
- KQL Querying
- Windows Telemetry Analysis
- Sysmon Monitoring
