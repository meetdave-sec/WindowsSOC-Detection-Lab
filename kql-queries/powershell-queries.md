# PowerShell Hunting Queries

## PowerShell Process Creation

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| sort by TimeGenerated desc
```

---

## Encoded PowerShell Commands

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "-enc"
```

---

## PowerShell Spawned Child Processes

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| where RenderedDescription has_any ("whoami.exe","net.exe","ipconfig.exe")
```

---

## PowerShell Network Activity

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| where RenderedDescription has "powershell.exe"
```

---

## Suspicious PowerShell Download Activity

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("Invoke-WebRequest","wget","curl","DownloadString")
```

---

## Skills Demonstrated

- KQL Querying
- Threat Hunting
- Process Monitoring
- Sysmon Telemetry Analysis
- Microsoft Sentinel Investigation
