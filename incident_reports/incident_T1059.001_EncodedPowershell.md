# Incident Report – Encoded PowerShell Execution

## Executive Summary

A Splunk alert triggered in the SOC lab environment for encoded PowerShell execution on the monitored Windows 10 virtual machine.

The alert was generated from Sysmon process creation telemetry and successfully identified the use of the `-EncodedCommand` parameter in PowerShell.

The activity was reviewed and confirmed to be a controlled lab simulation.

---

## Alert Details

**Alert Name:** Encoded PowerShell Execution Detected

Trigger Logic: Results greater than 0 within the configured alert time window.

Affected Asset

Hostname: Windows 10 SOC Lab VM
Role: Monitored Endpoint
Telemetry Source: Sysmon
Monitoring Platform: Splunk SIEM

**Detection Query:**

```spl
index=main Image="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

## Investigation Steps

Reviewed the triggered alert in Splunk.

Confirmed the detection matched a Sysmon Event ID 1 process creation event.

Examined the command line associated with the PowerShell process.

Verified that the process included the -EncodedCommand parameter.

Correlated the event with the lab simulation activity performed on the Windows endpoint.

## Findings

The investigation confirmed that PowerShell executed an encoded command on the monitored endpoint.

The command matched the expected lab simulation and was successfully detected by the custom SPL rule configured in Splunk.

The event demonstrated that Sysmon process creation telemetry and Splunk detection logic were functioning correctly.

## Evidence Reviewed

Encoded PowerShell command execution:

<img src="../screenshots/commands/EncodedPowershellComandRun.PNG" width="800"/>

Splunk detection result:

<img src="../screenshots/logs/EncodedPowershellResultSplunk.PNG" width="800"/>

Splunk alert configuration:

<img src="../screenshots/alerts/EncodedPowershellAlert.PNG" width="800"/>

## MITRE ATT&CK Mapping

Primary Technique:
T1059.001 – Command and Scripting Interpreter: PowerShell

Supporting Technique:
T1132 – Data Encoding

## Outcome

The alert successfully detected the simulated encoded PowerShell activity.

No additional containment actions were required because the event was part of a controlled lab exercise.

