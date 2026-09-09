# Timeline - Lab 70: MSBuild Abuse Investigation

## Investigation Timeline

This timeline reconstructs the major events associated with the controlled MSBuild investigation using the available command output and Windows telemetry.

## Timeline

| Date | Time | Event | Evidence | Assessment |
|---|---|---|---|---|
| 2026-06-25 | 07:48:50 | MSBuild.exe last-write timestamp | File metadata | Existing Microsoft binary |
| 2026-08-02 | 06:30:13 | MSBuild.exe creation timestamp | File metadata | Existing system binary |
| 2026-09-09 | 07:06 | MSBuild lab directory created | PowerShell | Lab preparation |
| 2026-09-09 | 07:18:49 | PowerShell Event ID 4104 observed | PowerShell Operational | Baseline telemetry |
| 2026-09-09 | 07:53:44 | PowerShell Event ID 4104 observed | PowerShell Operational | Baseline telemetry |
| 2026-09-09 | 08:00:01 | SafeBuild.proj timestamp updated | File metadata | Project preparation |
| 2026-09-09 | 08:00:30 | MSBuild.exe executed | PowerShell / MSBuild output | Controlled execution |
| 2026-09-09 | 08:00:30 | Sysmon Event ID 1 recorded | Sysmon Operational | Primary process evidence |
| 2026-09-09 | 08:00:39 | Sysmon Event ID 1 observed | Sysmon Operational | Related telemetry |
| 2026-09-09 | 08:01:26 | Sysmon Event ID 1 observed | Sysmon Operational | Related telemetry |

## Key Event: 09-09-2026 08:00:30

The most important event occurred at:

```text
09-09-2026 08:00:30
```

At this time, the controlled MSBuild project was executed.

The command used was:

```text
"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "C:\MSBuildAbuseLab\SafeBuild.proj" /t:Lab70
```

The corresponding Sysmon Event ID 1 recorded:

```text
Description: MSBuild.exe
FileVersion: 4.8.9037.0
Product: Microsoft .NET Framework
Company: Microsoft Corporation
OriginalFileName: MSBuild.exe
```

User:

```text
DESKTOP-GVRECLF\abhin
```

Current directory:

```text
C:\Windows\system32\
```

## Timeline Interpretation

The investigation followed this sequence:

1. MSBuild discovery
2. Binary validation
3. Lab directory preparation
4. SafeBuild.proj creation
5. Controlled MSBuild execution
6. Sysmon Event ID 1
7. Timestamp correlation
8. Investigation conclusion

## PowerShell Telemetry Context

PowerShell Event ID 4104 events were observed before the controlled MSBuild execution.

Relevant timestamps included:

```text
09-09-2026 07:18:49
09-09-2026 07:53:44
```

These events demonstrate that PowerShell Script Block Logging was active.

However, the available evidence does not establish that these events directly caused or initiated the MSBuild execution.

## Evidence Correlation

| Evidence | Timestamp | Relevance |
|---|---|---|
| Lab directory creation | 07:06 | Lab preparation |
| PowerShell Event ID 4104 | 07:18:49 | Baseline telemetry |
| PowerShell Event ID 4104 | 07:53:44 | Baseline telemetry |
| Project file modification | 08:00:01 | Project preparation |
| MSBuild execution | 08:00:30 | Primary execution event |
| Sysmon Event ID 1 | 08:00:30 | Primary process evidence |
| Sysmon Event ID 1 | 08:00:39 | Related telemetry |
| Sysmon Event ID 1 | 08:01:26 | Related telemetry |

## Important Timestamp Note

The timeline is based only on timestamps visible in the collected evidence.

It should therefore be treated as an evidence-based reconstruction rather than a complete timeline of every endpoint event.

## Final Timeline Assessment

The available evidence supports the following sequence:

1. MSBuild was discovered on the Windows endpoint.
2. The selected MSBuild executable was validated.
3. A dedicated investigation directory was prepared.
4. A benign project file was created.
5. The project was executed using MSBuild.exe.
6. Sysmon Event ID 1 captured the process creation.
7. The Sysmon command line identified the MSBuild executable and project file.
8. The execution timestamp matched the controlled execution.
9. The build completed successfully.
10. No evidence of malicious payload execution was identified.

## Final Timeline Finding

Controlled MSBuild execution confirmed at 09-09-2026 08:00:30.

No evidence of malicious payload execution was identified in the available telemetry.
