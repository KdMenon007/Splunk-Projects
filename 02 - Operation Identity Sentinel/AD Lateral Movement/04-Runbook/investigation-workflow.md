# AD Lateral Movement Investigation Workflow

## 1. Establish the discovery timeline

Review Sysmon Event 1 for `nltest`, `net user`, `net group`, `net view`, and `net localgroup` command lines. Review PowerShell Event 4104 for `Get-ADUser`, `Get-ADGroupMember`, and `Get-ADComputer`. Determine whether the host and user normally perform this activity.

## 2. Identify source and destination

- **Source-side evidence:** Event 4648 for explicit credentials; Sysmon Event 1 for the initiating command and process.
- **Destination-side evidence:** Event 4624 for successful logon, Event 5140 for share access, Event 7045 for service installation, Sysmon Event 1 for child processes, and Sysmon Event 17 for named pipes.
- Correlate by time, account, target host, source address, logon/session identifiers where available, and PsExec pipe names. Account for clock differences and field naming differences.

## 3. Investigate administrative-share access

Identify access to `ADMIN$` and `C$`. Compare source IP, account, destination hosts, time of day, and the user's normal share-access baseline. One source reaching multiple servers quickly is a lead, not proof by itself.

## 4. Validate PsExec indicators

Look for a destination-side service installation (often `PSEXESVC` / `%SystemRoot%\PSEXESVC.exe`), processes spawned by `PSEXESVC.exe`, named pipes resembling `\PSEXESVC-<source-host>-<pid>-stdin/stdout/stderr`, and source-side PsExec process creation. Consider renamed service names and alternative remote execution tools.

## 5. Document conclusion

Record the hypothesis, supporting events, source/destination, user running the source process, credentials/account observed, time window, baseline comparison, alternative explanations, confidence, and recommended containment or hardening actions. Avoid recording any plaintext password.


## 6. Trace RDP chaining

1. Start with suspicious activity on the destination (for example, discovery commands on the Domain Controller).
2. Take the Sysmon Event 1 `LogonId` and correlate it with Security Event 4624 on the same destination.
3. Review `Logon_Type`, `Source_Network_Address`, user, timestamp, and `Logon_ID`. Type 10 indicates a RemoteInteractive logon; a Type 3 shortly before it may be NLA.
4. Map the source address to a machine account/hostname using available authentication evidence.
5. On the source/intermediate host, search Sysmon Event 1 for `mstsc.exe`; correlate that process's Logon ID with Event 4624 on that host.
6. Repeat backward until the earliest observed hop is reached. Keep the distinction between an identified source host and a confirmed original compromise point.

## 7. Challenge chain: `svcupdate`

Correlate Event 5140 on `THM-SHR-SRV`, Event 7045 for the service path, Sysmon Event 1 command lines, and Event 4624 source-address evidence. The supplied chain points to `THM-HR-WS` (`10.5.50.15`) using `ryan.chen`. Confirm timestamps and raw fields; treat service installation as a strong lead rather than standalone proof of PsExec or maliciousness.
