# windows-dfir-lab70-msbuild-abuse-investigation
## Overview

MSBuild.exe is the Microsoft Build Engine. It is a legitimate Windows/.NET component used to build applications from project files, commonly .csproj, .vbproj, and related XML-based project definitions.

Because MSBuild is a trusted Microsoft executable, its execution does not automatically indicate malicious activity.

Attackers can sometimes abuse legitimate build functionality to execute code through specially crafted MSBuild project files. This is commonly investigated as trusted binary abuse or Living-off-the-Land behavior.

The important DFIR question is therefore not:

“Was MSBuild.exe executed?”

Instead, we ask:

“Why was MSBuild.exe executed, what project file did it process, who launched it, and what happened as a result?”

A normal development workstation might legitimately contain:

MSBuild.exe → Visual Studio / .NET project

A suspicious execution chain might instead look like:

PowerShell / cmd.exe
        ↓
MSBuild.exe
        ↓
Unusual .proj / .xml file
        ↓
Unexpected child process or artifact

Therefore, the investigation concentrates on process ancestry, command line, project-file location, file creation, and surrounding telemetry.
The presence of MSBuild.exe is not itself an IOC.

We need to determine whether:

MSBuild was executed from the expected Microsoft location.
The file is legitimate and signed.
The command line references a normal project or an unusual file.
The parent process makes sense.
A project file appeared in a suspicious directory.
MSBuild execution produced unexpected child processes or files.

This lab investigates MSBuild.exe, a legitimate Microsoft build utility that can be abused by threat actors for trusted binary execution.

The investigation focuses on identifying MSBuild execution through Sysmon Event ID 1, validating the MSBuild binary, examining the command line, identifying the project file involved, and correlating the execution with endpoint telemetry.

The lab uses a benign MSBuild project. No malicious payload, persistence mechanism, credential theft, process injection, or destructive activity was performed.

## Lab Objectives

- Understand how MSBuild abuse can be used as a trusted binary execution technique.
- Identify MSBuild installations on a Windows endpoint and validate the selected executable.
- Collect and examine file metadata, SHA256 hash, and Authenticode signature to establish binary legitimacy.
- Create and execute a controlled MSBuild project using MSBuild.exe.
- Detect the execution through Sysmon Event ID 1 (Process Creation).
- Analyze the MSBuild command line to identify the executable and project file involved.
- Correlate the MSBuild execution with available PowerShell and endpoint telemetry.
- Build a timeline around the project creation, execution, and process creation events.
- Distinguish between legitimate MSBuild execution and indicators that could suggest MSBuild abuse.
- Map the investigation to MITRE ATT&CK T1127.001 – MSBuild.
- Document the evidence and determine whether the observed activity should be classified as benign or suspicious.


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

A Windows endpoint generates a process creation event for MSBuild.exe, a legitimate Microsoft .NET Framework utility. Since MSBuild can also be abused to execute code, the SOC analyst must determine whether the execution is legitimate or suspicious.

In this controlled lab, a benign MSBuild project is executed and investigated using:

- MSBuild binary and signature validation
- Project file and command-line analysis
- Sysmon Event ID 1
- PowerShell telemetry
- Timeline correlation

The investigation concludes by determining whether the observed MSBuild activity represents legitimate execution or potential abuse.

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

