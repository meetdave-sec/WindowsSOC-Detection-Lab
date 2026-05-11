# Logs Analysis

## Overview

This folder contains investigation notes and telemetry analysis performed using Sysmon logs and Microsoft Sentinel.

The goal of this analysis is to:

- Understand Windows telemetry behavior
- Investigate suspicious activity
- Analyze process execution patterns
- Improve SOC analyst workflows
- Build detection engineering skills

---

# Analysis Areas

## Process Creation Analysis

Investigation of Sysmon Event ID 1 process creation telemetry.

Analysis includes:

- Parent-child process relationships
- Command-line arguments
- PowerShell execution
- Suspicious binaries

---

## PowerShell Telemetry Analysis

Analysis of PowerShell-related activity generated during simulations.

Focus areas:

- Encoded commands
- Spawned child processes
- Reconnaissance behavior
- Suspicious command execution

---

## Network Activity Analysis

Investigation of Sysmon Event ID 3 network connection logs.

---

## Registry Modification Analysis

Analysis of Sysmon Event ID 13 registry modification events used for persistence detection.

---

# Analysis Workflow

The general investigation workflow includes:

1. Generate telemetry
2. Collect logs in Sentinel
3. Query logs using KQL
4. Analyze suspicious behavior
5. Validate detections
6. Document findings

---

# Telemetry Sources

- Sysmon Operational Logs
- Windows Security Logs
- Microsoft Sentinel Queries
- KQL Hunting Queries

---

# Skills Demonstrated

- Log Analysis
- KQL Querying
- Process Investigation
- Threat Hunting
- Windows Telemetry Analysis
- Microsoft Sentinel Investigation
