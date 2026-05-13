# Persistence Hunting Queries

## Registry Run Key Persistence Detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| where RenderedDescription has "CurrentVersion\\Run"
| sort by TimeGenerated desc
```

Purpose:
Detect registry Run Key persistence activity commonly associated with malware and post-exploitation techniques.

---

## Scheduled Task Persistence Detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "schtasks"
| sort by TimeGenerated desc
```

Purpose:
Detect scheduled task persistence activity and suspicious usage of schtasks.exe.

---

## Broad Registry Modification Monitoring

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| sort by TimeGenerated desc
```

Purpose:
Monitor general registry modification activity using Sysmon Event ID 13 telemetry.

---

## Suspicious Startup Folder Persistence

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where RenderedDescription has_any ("Startup","Start Menu\\Programs\\Startup")
| sort by TimeGenerated desc
```

Purpose:
Detect startup folder persistence techniques that automatically execute payloads during user login.

---

## Scheduled Task Creation Monitoring

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "/create"
| where RenderedDescription has "schtasks"
| sort by TimeGenerated desc
```

Purpose:
Identify scheduled task creation activity and investigate suspicious persistence behavior.

---

## PowerShell Spawned Scheduled Tasks

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| where RenderedDescription has "schtasks.exe"
| sort by TimeGenerated desc
```

Purpose:
Detect PowerShell-driven scheduled task persistence activity frequently associated with post-exploitation behavior.

---

## Registry Persistence by User

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| project TimeGenerated, UserName, Computer, RenderedDescription
| sort by TimeGenerated desc
```

Purpose:
Identify users responsible for registry persistence activity and investigate suspicious behavior patterns.

---

## Persistence Payload Investigation

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13 or EventID == 1
| where RenderedDescription has_any ("powershell.exe","cmd.exe","notepad.exe")
| sort by TimeGenerated desc
```

Purpose:
Investigate executables configured within persistence-related telemetry and identify suspicious payload activity.

---

# Skills Demonstrated

- Threat Hunting
- Persistence Detection
- Registry Monitoring
- Scheduled Task Monitoring
- KQL Querying
- Sysmon Analysis
- Microsoft Sentinel
- Behavioral Analysis
