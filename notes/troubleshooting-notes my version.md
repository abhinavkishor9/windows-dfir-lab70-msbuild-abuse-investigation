# Troubleshooting Notes 

## 1. MSBuild Discovery

### Issue

MSBuild.exe needed to be located before the investigation could begin.

### Command

```powershell
Get-ChildItem "$env:windir\Microsoft.NET" -Recurse -Filter "MSBuild.exe" -ErrorAction SilentlyContinue |
Select-Object FullName, Length, LastWriteTime
```

### Result

Multiple MSBuild binaries were found.

The binary selected for the lab was:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
```

The 64-bit version was also present:

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
```

## 2. MSBuild Version Validation

The executable was tested before project creation.

Command:

```powershell
& "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" -version
```

Expected result:

```text
Microsoft (R) Build Engine version 4.8.9037.0
```

The successful output confirmed that MSBuild was installed and functional.

## 3. Lab Directory Preparation

The investigation used:

```text
C:\MSBuildAbuseLab
```

The directory was created using:

```powershell
New-Item -Path "C:\MSBuildAbuseLab" -ItemType Directory -Force
```

During preparation, the directory was also removed and recreated:

```powershell
Remove-Item "C:\MSBuildAbuseLab" -Recurse -Force
```

This was part of normal lab artifact preparation and was not a remediation action.

## 4. Project File Validation

The project directory was checked with:

```powershell
Get-ChildItem "C:\MSBuildAbuseLab" |
Select-Object Name, Length, CreationTime, LastWriteTime
```

The expected project file was:

```text
SafeBuild.proj
```

The project contents were verified using:

```powershell
Get-Content "C:\MSBuildAbuseLab\SafeBuild.proj"
```

## 5. Project Execution

The project was executed with:

```powershell
& "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "C:\MSBuildAbuseLab\SafeBuild.proj" /t:Lab70
```

The execution completed successfully:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
```

This confirmed that the project syntax and MSBuild execution were functioning correctly.

## 6. Existing MSBuild Process Check

Before execution, the process list was checked:

```powershell
Get-Process |
Where-Object {$_.ProcessName -eq "MSBuild"} |
Select-Object Id, ProcessName, Path
```

No MSBuild process was returned.

This was expected because the controlled execution had not yet occurred.

## 7. Sysmon Event ID 1 Validation

After execution, Sysmon Event ID 1 was reviewed.

The relevant event was recorded at:

```text
09-09-2026 08:00:30
```

The event identified:

```text
MSBuild.exe
```

The command line matched the controlled execution command.

This confirmed that Sysmon was successfully recording process creation telemetry.

## 8. High Sysmon Event Volume

The Sysmon Event Viewer showed a high volume of events.

Observed values:

```text
Total events: 47,266
Event ID 1 events: 10,256
```

Reviewing all events manually would be inefficient.

A better investigation approach is to filter by:

- Event ID
- Process name
- Time range
- Command line
- User
- Executable path

For this lab, Event ID 1 was the primary filter.

## 9. PowerShell Event Volume

PowerShell Operational logging also contained a large number of Event ID 4104 events.

Observed values:

```text
Total events: 859
Event ID 4104 events: 462
```

Large volumes of Script Block Logging events are normal on active Windows systems.

The analyst should narrow the investigation using:

- Time range
- User
- Host
- Script content
- Process relationships
- Suspicious keywords
- Related Sysmon events

## 10. Timestamp Correlation

The controlled MSBuild execution occurred at approximately:

```text
09-09-2026 08:00:30
```

Sysmon Event ID 1 recorded the MSBuild process creation at:

```text
09-09-2026 08:00:30
```

The matching timestamp provides strong evidence that the Sysmon event corresponds to the controlled execution.

## 11. Investigation Limitation

This lab demonstrated MSBuild process execution but did not simulate a malicious MSBuild payload.

The following behaviors were therefore outside the scope of the lab:

- Malicious child-process creation
- Command shell execution
- Network beaconing
- Persistence
- Credential access
- Process injection
- Payload download
- File encryption
- Destructive activity

Their absence should not be interpreted as proof that MSBuild cannot be used for such activity in real-world attacks.

