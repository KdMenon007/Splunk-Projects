# Project 2 — Identity Sentinel: Detecting AD Lateral Movement

**Organization scenario:** CatchMe  
**Status:** **Completed for the supplied lab scope** — AD discovery, source/destination correlation, SMB administrative-share activity, PsExec-style remote execution, and RDP chaining have been documented with SPL queries and screenshot evidence. This means the portfolio investigation workflow is assembled; it does not imply a production deployment or independent validation of every query in another Splunk environment.

> This module belongs under **Project 2: Identity Sentinel**, not Operation Splunk Watchtower. Project 2's Module 1 is **Initial Access**; this is the lateral-movement module.

## Investigation coverage

1. **AD discovery:** identify domain discovery commands in Sysmon Event 1 and PowerShell Event 4104.
2. **Source/destination correlation:** pivot between explicit credentials (Event 4648), successful logons (Event 4624), source addresses, accounts, and process Logon IDs.
3. **SMB administrative-share activity:** review Event 5140 and (when enabled) Event 5145.
4. **PsExec-style remote execution:** correlate destination service installation (Event 7045), child process creation (Sysmon Event 1), named pipes (Sysmon Event 17), and source-side execution.
5. **RDP chaining:** use suspicious process activity on the Domain Controller, correlate Logon IDs to Event 4624 / Logon Type 10, identify the source IP/host, find `mstsc.exe` on the intermediate server, and trace the previous hop.
6. **Challenge investigation:** reconstruct the `THM-HR-WS` → SMB/ADMIN$ → `svcupdate` service / command execution → `THM-SHR-SRV` chain from the supplied lab events.

## Package contents

- `01-Notes/` — source notes for AD discovery, SMB, PsExec, RDP chaining, and the challenge investigation.
- `02-SPL-Queries/` — standalone SPL query files for discovery, explicit credentials, share access, PsExec, RDP chaining, and challenge event correlation.
- `03-Evidence-Screenshots/` — diagrams and Splunk evidence supplied for this module. The credential-bearing command-line screenshot remains redacted in the package.
- `04-Runbook/` — investigation workflow and validation checklist.
- `documentation/evidence-register.csv` — evidence inventory.

## Key event references

| Event / artifact | Investigation use |
|---|---|
| Security 4624, Logon Type 10 | Successful RemoteInteractive/RDP logon on destination |
| Security 4624, Logon Type 3 | Network logon; may also appear as part of NLA before RDP Type 10 |
| Security 4648 | Explicit credential use on the source host, when applicable |
| Security 5140 / 5145 | Share access / detailed share access, subject to audit policy |
| System 7045 | New service installation; useful for PsExec-like behavior but not proof by itself |
| Sysmon 1 | Process creation and command-line context |
| Sysmon 17 | Named-pipe creation, potentially useful for PsExec correlation |
| Sysmon 4104 / PowerShell logging | Script-block evidence for AD discovery when logging is enabled |

## Investigation conclusions

### RDP chaining

The supplied evidence shows discovery commands on `THM-DC` associated with Logon ID `0x508C55A`; the matching successful logon indicates Logon Type 10 and source address `10.5.30.120`. An `mstsc.exe` process was then observed on `THM-SQL-SRV` with Logon ID `0x3C572BD`; the matching logon on that server identifies a previous source address of `10.5.50.12`. Together, these artifacts support a multi-hop RDP path. Validate the source-host mapping and account context against the complete raw events before making a stronger attribution.

### SMB / service-install challenge

The supplied challenge evidence associates `THM-HR-WS` (`10.5.50.15`) and account `ryan.chen` with administrative-share activity on `THM-SHR-SRV`, followed by a `svcupdate` service path under `%SystemRoot%` and command execution including `hostname`, `whoami`, and `ipconfig`. The correlation supports an SMB-based remote execution chain. It does not, by itself, prove the specific tool used or malicious intent.

## Validation and evidence cautions

- Queries use `index=win` or `index=challenge` and field names from the supplied lab. Verify the index, sourcetype, exact field casing, and event coverage before reuse.
- Event 5140/5145 availability depends on file-share auditing. Event 4648 only covers explicit credential use and does not cover every credential-reuse technique.
- Event 7045 means a service was installed; it is not automatically malicious and does not prove PsExec without corroboration.
- A Type 3 logon shortly before Type 10 may be associated with Network Level Authentication (NLA); correlate timestamps, source address, account, and destination.
- Counts and timestamps in screenshots describe the captured lab session, not current state.
- Never publish plaintext passwords, tokens, or sensitive customer data. The credential-bearing command-line screenshot is redacted.

## Status

The **AD lateral-movement portfolio module is complete for the supplied lesson and challenge evidence**. Operational validation in a separate Splunk environment remains environment-dependent.
