# Reconnaissance Hunting Queries

## Reconnaissance Command Detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("whoami.exe","hostname.exe","ipconfig.exe","tasklist.exe","net.exe")
| sort by TimeGenerated desc
```

Purpose:
Detect common reconnaissance and discovery commands frequently executed during post-exploitation activity.

---

## PowerShell Spawned Reconnaissance Activity

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| where RenderedDescription has_any ("whoami.exe","hostname.exe","ipconfig.exe","tasklist.exe","net.exe")
| sort by TimeGenerated desc
```

Purpose:
Identify reconnaissance commands launched from PowerShell, commonly associated with attacker enumeration behavior.

---

## Account Discovery Detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "net.exe"
| where RenderedDescription has "user"
| sort by TimeGenerated desc
```

Purpose:
Detect local account enumeration activity using net user commands.

---

## Network Discovery Monitoring

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "ipconfig.exe"
| sort by TimeGenerated desc
```

Purpose:
Monitor network configuration discovery activity performed using ipconfig.exe.

---

## Process Discovery Monitoring

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "tasklist.exe"
| sort by TimeGenerated desc
```

Purpose:
Identify process enumeration activity using tasklist.exe.

---

## User Discovery Monitoring

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "whoami.exe"
| sort by TimeGenerated desc
```

Purpose:
Detect user discovery activity using whoami.exe.

---

## Sequential Reconnaissance Activity

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("whoami.exe","hostname.exe","ipconfig.exe","tasklist.exe","net.exe")
| project TimeGenerated, Computer, RenderedDescription
| sort by TimeGenerated asc
```

Purpose:
Investigate sequential reconnaissance activity and identify behavioral chains during attacker enumeration.

---

# Important SOC Concept

Individual reconnaissance commands may be legitimate administrative activity.

However, multiple discovery commands executed sequentially may indicate:
- attacker reconnaissance
- post-exploitation activity
- environment discovery
- hands-on-keyboard intrusion behavior

Behavioral context is critical during investigations.

---

# Skills Demonstrated

- Threat Hunting
- Reconnaissance Detection
- Behavioral Analytics
- Process Correlation
- KQL Querying
- Sysmon Analysis
- Microsoft Sentinel
- SOC Investigation
