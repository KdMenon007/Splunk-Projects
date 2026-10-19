# Detection Playbook --- Suspicious Account Creation Command Line

**Status:** Draft playbook for lab validation; not yet a
production-ready detection.

## Purpose

Guide a SOC analyst through reviewing process telemetry that contains
account-creation command patterns such as `net user ... /add`.

## Trigger

A search or alert identifies a process command line matching a
local-account creation pattern. The current evidence includes a
screenshot with a `net user /add` command string; it does not prove
successful execution.

## Triage

1.  Confirm the event source, index, sourcetype, time range, and field
    extraction.
2.  Capture host, timestamp, user, process image, process ID, parent
    process ID, parent command line, and full command line.
3.  Determine whether the command is expected administration or approved
    automation.
4.  Correlate with account-management/security events around the same
    timestamp.
5.  Check subsequent logons and activity by the created account, if
    account creation is corroborated.
6.  Preserve raw events and document any telemetry gaps.

## Example hunt query

``` spl
index=windowslogs EventID=1
| search "net user"
| table _time host User Image ParentProcessId ProcessId ParentCommandLine CommandLine
| sort _time
```

Validate that the dataset's `EventID=1` is process-creation telemetry
and that the listed fields exist. This is a hunting query, not a
validated production detection.

## Escalation criteria

Escalate when corroborating evidence indicates an unauthorized account
was created, the command is unexplained, or follow-on activity is
suspicious. Follow organizational policy; do not disable accounts or
isolate endpoints solely on this screenshot.

## Closure criteria

Record a disposition, supporting events, rationale, affected
host/account (if confirmed), containment or remediation steps (if
authorized), and lessons learned.
