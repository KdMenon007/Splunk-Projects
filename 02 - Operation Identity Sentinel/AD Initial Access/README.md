# Project 2 — Detecting Active Directory Initial Access

**Scenario organization:** CatchMe  
**Project family:** Splunk SIEM / Threat Hunting  
**Status:** In progress — initial evidence reviewed; more evidence may be added.

## Objective
Investigate potential initial access to an Active Directory-connected environment by correlating IIS access logs, Exchange/OWA authentication patterns, Windows Security events, and Sysmon telemetry.

This package covers four evidence streams that must remain separate unless host, source, account, and normalized timestamps establish a relationship:
1. **Original IIS `shell.aspx` path:** scanning → suspicious ASP.NET endpoint → possible upload → web-shell requests → `w3wp.exe` child-process execution.
2. **OWA credential path:** repeated authentication POSTs → failed-login indicators → Windows authentication events → post-login activity.
3. **VPN / RADIUS / NPS path:** NPS denials → Windows 4625/4624 timeline → DC credential-validation and post-authentication pivots.
4. **Separate IIS `error.aspx` path:** 404 scanning lead → successful endpoint requests → command-like query parameters → upload POST → Sysmon file-create event. See `01-investigation-notes/iis-error-aspx-threat-hunting-scenario.md`.

## Structure
- `01-investigation-notes/` — evidence-led report, VPN/RADIUS/NPS investigation notes, findings, limitations, and next actions.
- `02-splunk-queries/` — reusable SPL queries and query notes.
- `03-evidence/screenshots/` — supplied screenshots renamed descriptively.
- `04-documentation/` — evidence register, timeline template, validation checklist, workflow.
- `05-reference-material/` — original notes and AD authentication reference.

## Initial evidence summary
- A captured IIS search shows **114 404 events** for source `203.0.113.47`.
- A source-IP pivot shows **163 matching IIS events** and **120 distinct URI values** in the captured result set.
- Screenshots show requests to `/owa/auth.owa`, `/owa/auth/logon.aspx`, `/aspnet_client/system_web/shell.aspx`, and `/internalapp/upload.aspx`.
- A POST request references `file=shell.aspx`; a Sysmon Event ID 11 screenshot shows a file ending in `shell.aspx` under `C:\inetpub\wwwroot\aspnet_client\system_web\`.
- Process telemetry shows `w3wp.exe` associated with `cmd.exe` commands such as `whoami`, `ipconfig`, `net user`, `net localgroup administrators`, `dir C:\Users`, and `systeminfo`.
- OWA screenshots show repeated POSTs, a five-minute bucket with 16 requests, and a redirect example containing `reason=2`.
- A visible Windows timeline has a 4624 event before a later cluster of 4625 events. It does **not** establish “failures followed by success.”

## Important caveats
- `203.0.113.47` is in TEST-NET-3, reserved for documentation. Treat it as sanitized lab data, not real attacker attribution.
- IIS timestamps are normally UTC; Windows event timestamps may be local. Normalize time before correlation.
- HTTP `302` alone does not prove successful OWA authentication.
- `w3wp.exe` spawning `cmd.exe` with reconnaissance commands is highly suspicious in this scenario. `csc.exe` may be legitimate ASP.NET compilation and needs context.
- Validate index, sourcetype, host, field names, and time range against raw events.
- Counts and timestamps are observations from screenshots, not complete or guaranteed current results.

## Next actions
1. Confirm indexes, sourcetypes, hosts, and field names for IIS, Sysmon, and Windows Security.
2. Re-run searches over a consistent window and normalize timestamps.
3. Verify whether the POST, file-create event, shell requests, and process events share a host and timeline.
4. Determine whether OWA evidence belongs to the same investigation or a separate example.
5. Expand scope to DC authentication, privileged-group changes, remote logons, services/tasks, PowerShell, lateral movement, and access to file/SQL servers.
6. Add new screenshots and update the evidence register as the project grows.


## Latest update — VPN / RADIUS / NPS evidence
- Added four supplied screenshots covering the VPN/NPS flow, NPS denials grouped by account and RADIUS client, the David Chen Windows authentication timeline, and the NPS field-mapping cross-check.
- Added `01-investigation-notes/vpn-radius-nps-investigation.md` and six SPL queries for NPS denial scope, NPS result timelines, Windows logons, reason codes, NTLM credential validation, and Kerberos pivots.
- Screenshot observation: 12 NPS 6273 events grouped as 10 for `david.chen`, one for `liam.patel`, and one for `michelle.smith`, all shown with client `10.5.10.200`. A separate Windows timeline shows ten 4625 events for David followed by one 4624 about five seconds after the last displayed failure.
- The NPS event screenshot has an account-field/filter mismatch; the successful NPS event is not considered verified for David until raw event fields are inspected. The NPS-to-Windows relationship remains a hypothesis pending correlation.


## Latest update — IIS `error.aspx` threat-hunting scenario
- Added a separate investigation note and five reusable SPL query files for the newly supplied screenshots.
- Added five screenshots covering 404 source counts, successful URI distribution, command-like requests, upload POST, and Sysmon Event ID 11.
- Screenshot observations: 21 captured 404 events from `198.51.100.23`; nine successful responses from that source; five requests to `/aspnet_client/system_web/error.aspx`; two to `/internalapp/upload.aspx`; one upload POST referencing `error.aspx`; and a matching file-create event on `THM-WEB-SRV.tryhatmestudios.thm`.
- Kept this scenario separate from the older `shell.aspx` / `203.0.113.47` evidence. These documentation-range IPs are sanitized example data, not real-world attribution.
- The chain remains a high-priority hypothesis pending raw-event, host, and normalized-timestamp validation.
