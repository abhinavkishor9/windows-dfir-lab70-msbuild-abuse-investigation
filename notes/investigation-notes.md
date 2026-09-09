# Investigation Notes - Lab 70: MSBuild Abuse Investigation

## 1. Investigation Objective

The objective of this investigation was to examine MSBuild execution from a Windows DFIR perspective and determine whether the controlled execution could be identified and validated through endpoint telemetry.

The investigation focused on process creation, command-line analysis, binary validation, project-file identification, user context, and timestamp correlation.

## 2. MSBuild Discovery

The first step was to identify MSBuild binaries installed on the system.

Command used:

```powershell
Get-ChildItem "$env:windir\Microsoft.NET" -Recurse -Filter "MSBuild.exe" -ErrorAction SilentlyContinue |
Select-Object FullName, Length, LastWriteTime
```

Multiple MSBuild binaries were identified.

The binary selected for the lab was:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
```

## 3. Version Validation

The selected MSBuild executable was tested with the `-version` parameter.

Command:

```powershell
& "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" -version
```

Result:

```text
Microsoft (R) Build Engine version 4.8.9037.0
[Microsoft .NET Framework, version 4.0.30319.42000]
```

This confirmed that MSBuild was installed and functional.

## 4. Binary Metadata

The binary metadata was collected before execution.

Command:

```powershell
Get-Item "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" |
Select-Object Name, FullName, Length, CreationTime, LastWriteTime
```

Observed values:

```text
Name          : MSBuild.exe
FullName      : C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
Length        : 255920
CreationTime  : 02-08-2026 06:30:13
LastWriteTime : 25-06-2022 07:48:50
```

## 5. Hash Collection

SHA256 was collected for the MSBuild executable.

Command:

```powershell
Get-FileHash "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" -Algorithm SHA256
```

Hash:

```text
5F9AF68DB10B029453264CFC9B8EEE4265549A2855BB79668CCFC571FB11F5FC
```

The hash was recorded as part of the investigation evidence.

## 6. Authenticode Validation

The digital signature was checked using:

```powershell
Get-AuthenticodeSignature "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
```

Result:

```text
Status: Valid
```

The result supports that the executable was a valid signed MSBuild binary.

## 7. Process Baseline

Before execution, the running process list was checked for an existing MSBuild process.

Command:

```powershell
Get-Process |
Where-Object {$_.ProcessName -eq "MSBuild"} |
Select-Object Id, ProcessName, Path
```

No MSBuild process was returned.

This established that there was no currently running MSBuild process during the baseline check.

## 8. Lab Directory

A dedicated directory was created:

```text
C:\MSBuildAbuseLab
```

The directory was used to contain the controlled project file.

Using a dedicated directory made the project artifact easier to identify during investigation and timeline analysis.

## 9. Project File Creation

The controlled project file was:

```text
C:\MSBuildAbuseLab\SafeBuild.proj
```

The project contained a target named:

```text
Lab70
```

The target only generated a harmless message:

```text
Lab 70-MSBuild Abuse Investigation executed successfully
```

No malicious code or payload was included.

## 10. Project Validation

The project contents were checked with:

```powershell
Get-Content "C:\MSBuildAbuseLab\SafeBuild.proj"
```

The project was confirmed to contain the expected `Lab70` target.

## 11. Controlled Execution

The project was executed using:

```powershell
& "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "C:\MSBuildAbuseLab\SafeBuild.proj" /t:Lab70
```

The build completed successfully.

Observed result:

```text
Build succeeded.
0 Warning(s)
0 Error(s)
Time Elapsed: 00:00:00.40
```

## 12. Sysmon Event Correlation

Sysmon Event ID 1 was reviewed after the execution.

The relevant process creation event occurred at:

```text
09-09-2026 08:00:30
```

The event identified:

```text
Description: MSBuild.exe
FileVersion: 4.8.9037.0
Product: Microsoft .NET Framework
Company: Microsoft Corporation
OriginalFileName: MSBuild.exe
```

The recorded command line was:

```text
"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "C:\MSBuildAbuseLab\SafeBuild.proj" /t:Lab70
```

This provides strong evidence that the controlled command was executed.

## 13. User Context

The Sysmon event recorded:

```text
User: DESKTOP-GVRECLF\abhin
```

This matched the expected user context for the lab.

## 14. Current Directory

Sysmon recorded:

```text
CurrentDirectory: C:\Windows\system32\
```

Current directory information can be useful when investigating suspicious trusted binary execution because it provides additional execution context.

## 15. PowerShell Telemetry

PowerShell Operational Event ID 4104 events were present during the investigation period.

Observed timestamps included:

```text
09-09-2026 07:18:49
09-09-2026 07:53:44
```

The presence of these events confirms that PowerShell Script Block Logging was active.

However, the available evidence does not establish that these events were directly responsible for the MSBuild execution.

## 16. Investigation Assessment

### Legitimate Execution Indicators

- MSBuild was located in an expected .NET Framework directory.
- The executable contained expected Microsoft metadata.
- Authenticode validation returned `Valid`.
- The file version matched the installed MSBuild version.
- The project file was intentionally created for the lab.
- The project performed only a harmless message operation.
- The build completed successfully.
- No malicious payload was used.

### Security-Relevant Indicators

- Sysmon Event ID 1 captured MSBuild execution.
- The complete command line was available.
- The project-file path was visible.
- User context was available.
- Execution timestamp was available.

## 17. DFIR Interpretation

The investigation demonstrates the difference between trusted binary execution and malicious trusted binary abuse.

MSBuild.exe is a legitimate Microsoft executable. Its execution alone is therefore insufficient to establish compromise.

A real-world investigation should correlate MSBuild activity with:

- Parent process
- Child processes
- Project-file location
- File creation
- Network connections
- User context
- Command-line parameters
- Script content
- Obfuscation
- Persistence mechanisms
- Other security telemetry

## 18. Final Finding

The investigation confirmed controlled execution of Microsoft MSBuild.

Executable:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
```

Project:

```text
C:\MSBuildAbuseLab\SafeBuild.proj
```

Execution time:

```text
09-09-2026 08:00:30
```

Primary telemetry:

```text
Sysmon Event ID 1
```

The available evidence does not demonstrate malicious payload execution.

### Final Classification

**BENIGN / CONTROLLED LAB ACTIVITY**

### Confidence

**High**

The confidence is based on the controlled project, expected executable path, valid signature, known command line, and harmless execution behavior.
