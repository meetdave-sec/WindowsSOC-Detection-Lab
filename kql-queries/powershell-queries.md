# PowerShell Hunting Queries

## PowerShell Process Creation

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| sort by TimeGenerated desc
```

Purpose:
Detect general PowerShell execution activity using Sysmon process creation telemetry.

---

## Encoded PowerShell Detection

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("-enc","EncodedCommand")
| sort by TimeGenerated desc
```

Purpose:
Detect Base64-encoded PowerShell command execution commonly associated with obfuscation techniques and suspicious scripting behavior.

---

## PowerShell Spawned Child Processes

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| where RenderedDescription has_any ("whoami.exe","net.exe","ipconfig.exe")
| sort by TimeGenerated desc
```

Purpose:
Identify reconnaissance-related child processes spawned from PowerShell sessions.

---

## PowerShell Network Activity

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| where RenderedDescription has "powershell.exe"
| sort by TimeGenerated desc
```

Purpose:
Detect PowerShell-generated network connection activity using Sysmon Event ID 3 telemetry.

---

## Suspicious PowerShell Download Activity

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("Invoke-WebRequest","DownloadString","wget","curl")
| sort by TimeGenerated desc
```

Purpose:
Detect PowerShell commands commonly associated with payload downloads and remote content retrieval.

---

## PowerShell Parent-Child Relationships

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| project TimeGenerated, Computer, RenderedDescription
```

Purpose:
Review PowerShell process relationships and investigate suspicious execution chains.

---

# Skills Demonstrated

- Threat Hunting
- KQL Querying
- Detection Engineering
- Sysmon Analysis
- Microsoft Sentinel
- Behavioral Analysis
