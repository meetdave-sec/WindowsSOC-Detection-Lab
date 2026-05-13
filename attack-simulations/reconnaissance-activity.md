# Reconnaissance Activity Attack Simulation

## Overview

This attack simulation demonstrates reconnaissance activity within the Windows SOC Detection Lab.

The objective was to simulate common post-exploitation discovery commands frequently executed by attackers after gaining access to a system.

The simulation validates Sysmon process creation telemetry and Microsoft Sentinel visibility into reconnaissance behavior.

---

# Simulation Objective

The purpose of this simulation was to:
- Generate reconnaissance telemetry
- Simulate attacker discovery behavior
- Validate Sysmon Event ID 1 monitoring
- Investigate process execution telemetry
- Analyze PowerShell-spawned reconnaissance activity

---

# Reconnaissance Commands Executed

The following commands were executed individually inside PowerShell:

```powershell
whoami
hostname
ipconfig
tasklist
net user
```

---

# Command Purpose

| Command | Purpose |
|---|---|
| whoami | Identify current user |
| hostname | Identify system hostname |
| ipconfig | Enumerate network configuration |
| tasklist | Enumerate running processes |
| net user | Enumerate local user accounts |

---

# Attack Simulation Screenshots

## Reconnaissance Commands — Part 1

![Recon Commands 1](../screenshots/recon-commands-1.png)

---

## Reconnaissance Commands — Part 2

![Recon Commands 2](../screenshots/recon-commands-2.png)

---

# Why Reconnaissance Matters

Attackers commonly perform reconnaissance to:
- Identify system details
- Discover user accounts
- Enumerate running processes
- Map network configuration
- Prepare for lateral movement
- Identify privilege escalation opportunities

Reconnaissance activity is heavily associated with:
- post-exploitation behavior
- threat actor enumeration
- attacker situational awareness
- environment discovery

---

# Expected Telemetry

This activity should generate:
- Sysmon Event ID 1 telemetry
- Process creation logs
- PowerShell-spawned process activity
- Command-line execution visibility
- Parent-child process relationships

Telemetry is forwarded into Microsoft Sentinel using:
- Azure Monitor Agent
- Azure Arc
- Data Collection Rules

---

# Important Security Concept

Individually, commands such as:
- whoami
- hostname
- ipconfig

are legitimate administrative tools.

However, multiple discovery commands executed sequentially from PowerShell may indicate:
- attacker reconnaissance
- post-exploitation activity
- hands-on-keyboard intrusion behavior

This demonstrates the importance of:
- behavioral analytics
- process correlation
- activity chaining

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

- Threat Simulation
- Reconnaissance Detection
- Process Monitoring
- Sysmon Analysis
- Microsoft Sentinel
- Threat Hunting
- Behavioral Detection
