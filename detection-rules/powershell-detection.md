# PowerShell Execution Detection

## Objective

The objective of this detection was to identify PowerShell execution activity using Sysmon process creation logs within Microsoft Sentinel.

---

## Detection Logic

The query filters Sysmon Event ID 1 logs for processes involving `powershell.exe`.

Sysmon Event ID 1 provides:
- Process execution details
- Parent-child relationships
- Command-line arguments
- User context

---

## KQL Query

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| sort by TimeGenerated desc
```

---

## Test Activity

The following commands were executed inside the Windows VM to generate telemetry:

```powershell
whoami
Get-Process
```

---

## Screenshot — PowerShell Detection Query

![PowerShell Detection Query](../screenshots/powershell-detection-query.png)

---

## Detection Result

Microsoft Sentinel successfully detected PowerShell-related process activity from Sysmon telemetry.

The query returned:
- powershell.exe activity
- spawned child processes
- associated timestamps
- endpoint hostname information

---

## MITRE ATT&CK Mapping

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |

---

## Skills Demonstrated

- KQL Querying
- Sysmon Analysis
- Microsoft Sentinel
- Process Creation Monitoring
- Detection Engineering
