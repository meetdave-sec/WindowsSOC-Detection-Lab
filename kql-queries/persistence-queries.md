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
| where EventID == 13
| where RenderedDescription has_any ("powershell.exe","cmd.exe","notepad.exe")
| sort by TimeGenerated desc
```

Purpose:
Investigate executables configured within persistence-related registry modifications.

---

## Registry Persistence Process Visibility

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| project TimeGenerated, Computer, RenderedDescription
```

Purpose:
Review persistence-related registry modification telemetry and investigate suspicious execution patterns.

---

# Skills Demonstrated

- Threat Hunting
- Persistence Detection
- Registry Monitoring
- KQL Querying
- Sysmon Analysis
- Microsoft Sentinel
- Behavioral Analysis
