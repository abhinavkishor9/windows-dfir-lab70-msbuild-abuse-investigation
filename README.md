# Lab 70: MSBuild Abuse Investigation

## Overview

This lab investigates MSBuild.exe, a legitimate Microsoft build utility that can be abused by threat actors for trusted binary execution.

The investigation focuses on identifying MSBuild execution through Sysmon Event ID 1, validating the MSBuild binary, examining the command line, identifying the project file involved, and correlating the execution with endpoint telemetry.

The lab uses a benign MSBuild project. No malicious payload, persistence mechanism, credential theft, process injection, or destructive activity was performed.

## Lab Objectives

- Understand the security risks associated with MSBuild abuse.
- Identify MSBuild execution using Sysmon Event ID 1.
- Analyze the MSBuild command line.
- Identify the project file supplied to MSBuild.
- Validate the MSBuild executable using metadata, SHA256, and Authenticode.
- Correlate process execution with timestamps.
- Distinguish legitimate MSBuild execution from suspicious MSBuild activity.
- Document the investigation using a DFIR workflow.
- Identify useful detection opportunities for trusted binary execution.

## Environment

| Component | Details |
|---|---|
| Operating System | Windows |
| Hostname | DESKTOP-GVRECLF |
| User | DESKTOP-GVRECLF\abhin |
| MSBuild Version | 4.8.9037.0 |
| .NET Framework | 4.0.30319.42000 |
| Sysmon | Enabled |
| Primary Sysmon Event | Event ID 1 - Process Create |
| PowerShell Logging | Event ID 4104 |
| Lab Directory | `C:\MSBuildAbuseLab` |
| Project File | `SafeBuild.proj` |

## Investigation Scenario

A SOC analyst observes MSBuild.exe executing on a Windows endpoint.

MSBuild is a legitimate Microsoft utility and can be used normally during software development and build operations. However, attackers may abuse trusted developer utilities to execute malicious content.

The investigation attempts to determine:

1. Whether MSBuild was executed.
2. Which MSBuild binary was executed.
3. Which project file was supplied to MSBuild.
4. Which user initiated the execution.
5. Whether the executable was authentic.
6. Whether suspicious behavior followed the execution.
7. Whether the available telemetry supports a malicious activity classification.

For this controlled lab, the project file was intentionally benign and only generated a harmless build message.

## MSBuild Binary Discovery

The system contained multiple MSBuild binaries.

The binary selected for the investigation was:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
```

The executable reported:

```text
Microsoft (R) Build Engine version 4.8.9037.0
[Microsoft .NET Framework, version 4.0.30319.42000]
```

## Binary Validation

The selected MSBuild executable was inspected before execution.

Observed metadata:

- Name: `MSBuild.exe`
- Path: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe`
- Size: `255920` bytes
- Creation Time: `02-08-2026 06:30:13`
- Last Write Time: `25-06-2022 07:48:50`
- File Version: `4.8.9037.0`
- Product: `Microsoft .NET Framework`
- Company: `Microsoft Corporation`
- Original Filename: `MSBuild.exe`

SHA256:

```text
5F9AF68DB10B029453264CFC9B8EEE4265549A2855BB79668CCFC571FB11F5FC
```

Authenticode:

```text
Status: Valid
```

The metadata and valid digital signature support that the executable was the expected Microsoft MSBuild binary.

## Lab Project

The controlled project was created at:

```text
C:\MSBuildAbuseLab\SafeBuild.proj
```

The project contained a target named `Lab70`.

The target only displayed a harmless message and did not execute malicious code or perform system modification.

## MSBuild Execution

The project was executed using:

```powershell
& "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "C:\MSBuildAbuseLab\SafeBuild.proj" /t:Lab70
```

The build completed successfully:

```text
Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed: 00:00:00.40
```

## Sysmon Evidence

Sysmon Event ID 1 captured the MSBuild process creation.

The event was recorded at:

```text
09-09-2026 08:00:30
```

Important fields included:

```text
Description: MSBuild.exe
FileVersion: 4.8.9037.0
Product: Microsoft .NET Framework
Company: Microsoft Corporation
OriginalFileName: MSBuild.exe
CurrentDirectory: C:\Windows\system32\
User: DESKTOP-GVRECLF\abhin
```

Recorded command line:

```text
"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "C:\MSBuildAbuseLab\SafeBuild.proj" /t:Lab70
```

The Sysmon timestamp directly corresponds with the controlled MSBuild execution.

## PowerShell Telemetry

PowerShell Operational Event ID 4104 events were present during the baseline period.

Observed events included:

- `09-09-2026 07:18:49`
- `09-09-2026 07:53:44`

The presence of PowerShell Event ID 4104 confirms that Script Block Logging was active.

However, the available 4104 evidence does not establish malicious MSBuild activity. The events therefore should not be treated as malicious without additional correlation.

## Investigation Findings

### Finding 1: MSBuild Execution Confirmed

Sysmon Event ID 1 confirmed that `MSBuild.exe` was executed.

### Finding 2: Expected Binary Location

The executable was located under:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\
```

This is consistent with a legitimate .NET Framework MSBuild installation.

### Finding 3: Valid Digital Signature

The MSBuild executable returned:

```text
Status: Valid
```

for Authenticode validation.

### Finding 4: Project File Identified

The command line clearly identified:

```text
C:\MSBuildAbuseLab\SafeBuild.proj
```

as the project processed by MSBuild.

### Finding 5: Controlled Execution

The project only generated a harmless message and completed successfully.

### Finding 6: No Malicious Payload Observed

The available evidence does not demonstrate:

- Malicious child-process execution
- Persistence
- Network communication
- Credential theft
- Process injection
- Payload download
- File encryption
- Destructive activity

## Detection Considerations

A detection rule should not alert solely because `MSBuild.exe` executes.

Higher-value detection conditions include:

- MSBuild executing from an unusual directory.
- MSBuild processing a project file from a user-writable directory.
- MSBuild launched by an unusual parent process.
- MSBuild spawning suspicious child processes.
- MSBuild creating executable or script files.
- MSBuild making unexpected network connections.
- Suspicious or obfuscated command-line parameters.
- MSBuild execution by an unusual user or service account.
- MSBuild activity correlated with PowerShell, `cmd.exe`, `wscript.exe`, `rundll32.exe`, or other suspicious processes.
- MSBuild execution associated with known malicious files or indicators.

## MITRE ATT&CK

This investigation is primarily associated with:

**T1127 - Trusted Developer Utilities Proxy Execution**

More specifically:

**T1127.001 - MSBuild**

## Evidence Summary

| Evidence | Observation | Assessment |
|---|---|---|
| MSBuild binary | Expected .NET Framework path | Legitimate |
| File version | 4.8.9037.0 | Expected |
| Digital signature | Valid | Legitimate |
| SHA256 | Recorded | Evidence |
| Project file | SafeBuild.proj | Benign lab artifact |
| Sysmon Event ID 1 | MSBuild process creation | Confirmed |
| Command line | Project path visible | Strong evidence |
| User | DESKTOP-GVRECLF\abhin | Expected lab user |
| Build result | Successful | Benign |
| Malicious payload | Not present | Not observed |
| Persistence | Not observed | Not observed |
| Network activity | Not demonstrated | Not observed |

## Lessons Learned

1. Legitimate Windows utilities can still be relevant to security investigations.
2. MSBuild execution should be evaluated using execution context rather than the process name alone.
3. Sysmon Event ID 1 provides valuable process creation evidence.
4. Command-line analysis is important when investigating trusted binary execution.
5. Binary path and digital signature validation help establish executable legitimacy.
6. Timeline correlation can confirm whether endpoint telemetry corresponds to the suspected execution.
7. A trusted binary does not automatically indicate malicious activity.


## Final Assessment

**Investigation Type:** Windows DFIR / Trusted Binary Execution

**Technique:** T1127.001 - MSBuild

**Primary Telemetry:** Sysmon Event ID 1

**Secondary Telemetry:** PowerShell Event ID 4104

**Execution Status:** Successful

**Payload:** Benign

**Final Finding:** Controlled MSBuild execution confirmed. No evidence of malicious payload execution was identified in the available telemetry.
