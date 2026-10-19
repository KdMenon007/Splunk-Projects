# Threat-Hunting Starter Plan --- Watchtower

## Scope

This is a hunt plan derived from the current Exploring SPL evidence. No
confirmed incident is asserted.

## Hunt A --- Possible account creation via command line

**Hypothesis:** A process command line containing `net user /add` may
indicate an attempt to create a local user account.

**Starting query**

``` spl
index=windowslogs EventID=1
| table _time host User ParentProcessId ProcessId ParentCommandLine CommandLine
| sort _time
```

Use only if these fields are present and `EventID=1` represents process
creation in this dataset.

**Investigate** 1. Record host, event time, user context, process ID,
parent process ID, image, and full command line. 2. Search for
corroborating account-management events near the same time. 3. Establish
whether the process was successful; command-line presence alone is
insufficient. 4. Check whether the account was authorized and whether
related logons or follow-on activity occurred. 5. Preserve relevant
events and document limitations.

**Disposition options:** benign/authorized, suspicious but unconfirmed,
confirmed policy violation, or insufficient evidence. Use only when
evidence supports the chosen outcome.

## Hunt B --- Successful logons and source context

**Hypothesis:** Grouping successful logons by account, source IP, and
logon type may reveal unusual patterns.

``` spl
index=windowslogs EventID=4624
| stats count by User IpAddress LogonType
| sort - count
```

Validate field names; Windows logon events often use fields that differ
by sourcetype or extraction configuration. Establish a baseline before
labeling activity anomalous.

## Hunt C --- RPC-related destination activity

**Starting query**

``` spl
index=windowslogs DestinationIp="172.18.39.6" DestinationPort=135
| table _time host User SourceIp DestinationIp DestinationPort
| sort _time
```

The supplied screenshot shows four matches. Port 135 alone is not a
malicious indicator. Correlate with process, endpoint, and network
context before escalating.

## Evidence requirements

For each hunt, retain: - Hypothesis and scope - Exact query and time
range - Result count and relevant raw events - Corroborating or
contradictory evidence - Analyst conclusion, confidence, and
limitations - Next action and owner (if applicable)

## Current status

Hunt ideas are documented; no confirmed threat finding has been
established from the supplied screenshots alone.
