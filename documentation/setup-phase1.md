# Windows SOC Detection Lab — Setup Phase 1

## Project Objective

The objective of this project is to build a Windows-based SOC detection lab using Sysmon and Microsoft Sentinel for centralized log monitoring, detection engineering, and threat hunting.

This lab is designed to simulate real-world SOC workflows involving:
- Windows telemetry collection
- SIEM integration
- KQL-based log analysis
- Detection engineering
- Threat investigation

---

## Initial Lab Architecture

Windows 11 VM  
↓  
Sysmon  
↓  
Azure Monitor Agent  
↓  
Log Analytics Workspace  
↓  
Microsoft Sentinel  

---

## Environment Setup

### Windows Virtual Machine
A Windows 11 virtual machine was deployed locally using virtualization software for endpoint monitoring and attack simulation.

### Microsoft Sentinel Setup
Microsoft Sentinel was configured using:
- Resource Group
- Log Analytics Workspace
- Microsoft Sentinel instance

### Azure Arc Integration
The local Windows VM was onboarded into Azure Arc to allow Azure-based monitoring and log collection.

---

## Setup Progress

Completed:
- Windows VM deployment
- Sysmon installation
- Azure Arc onboarding
- Data Collection Rule configuration
- Sentinel log ingestion

Pending:
- Detection engineering
- Attack simulation
- KQL threat hunting
- Alert creation
- Incident analysis

---

## Skills Covered

- Windows Logging
- SIEM Deployment
- Azure Arc
- Microsoft Sentinel
- Sysmon Configuration
- Log Ingestion
- KQL Fundamentals