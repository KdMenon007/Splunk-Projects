# Investigation Notes — Active Directory Initial Access

## Executive summary
The screenshots contain two high-value leads: (A) apparent IIS web-shell activity and (B) repeated OWA authentication activity. The IIS evidence is the stronger potential execution chain because the supplied screenshots show concentrated 404s, broad URI discovery, a POST referencing a shell filename, a Sysmon file-create event, shell-like request parameters, and `w3wp.exe` spawning `cmd.exe` commands.

The OWA evidence suggests repeated authentication attempts and provides Windows Security pivots. The screenshots include different timestamps and usernames, so they must not be combined into one incident until host, source, and normalized-time correlation confirms the relationship.

**Assessment:** High-priority suspicious activity in the lab evidence; incident scope and real-world attribution remain unconfirmed.

## Data sources
| Source | Fields / identifiers | Investigative value |
|---|---|---|
| IIS | `c_ip`, `cs_uri_stem`, `cs_uri_query`, `cs_method`, `sc_status` | Scanning, upload requests, shell access, source IP |
| Windows process telemetry | Event ID 1, `ParentImage`, `CommandLine` | Process ancestry and command execution |
| Sysmon file-create | Event ID 11, `TargetFilename` | Potential shell deployment |
| Windows Security | Event IDs 4624 and 4625 | Successful/failed logon context |
| Exchange/OWA | `/owa/auth.owa`, `/owa/auth/logon.aspx` | Repeated authentication POSTs and redirect parameters |

Field names and indexes shown in the screenshots (`iis`, `win`, `EventCode`) are lab-specific; confirm them before reuse.

## Evidence stream A — IIS reconnaissance and web-shell behavior

### A1. Concentrated 404 activity
The captured `index=iis sc_status=404 | stats count by c_ip` search shows **114 events** for `203.0.113.47`.

**Interpretation:** A burst of 404s from one source can indicate path enumeration, but scanners, crawlers, health checks, and misconfigured clients can also generate 404s. Treat it as a lead.

**IP caveat:** `203.0.113.47` is TEST-NET-3, a documentation-only range. Do not attribute it to a real external actor.

### A2. URI discovery
A source-IP pivot shows **163 matching events** and **120 URI values**. Screenshots include `/owa/auth.owa`, `/owa/auth/logon.aspx`, `/aspnet_client/system_web/shell.aspx`, and `/internalapp/upload.aspx`.

**Interpretation:** Broad URI enumeration followed by requests to an unexpected ASP.NET endpoint is consistent with discovery activity. A path alone does not prove exploitation.

### A3. Potential upload request
A captured IIS event shows a POST to `/internalapp/upload.aspx` with `file=shell.aspx` and status `200`.

**Interpretation:** Review the upload handler and correlate it with file creation. HTTP 200 means a response was returned; it does not prove a file was written or executed.

### A4. Suspicious ASP.NET file and requests
A Sysmon Event ID 11 screenshot shows `C:\inetpub\wwwroot\aspnet_client\system_web\shell.aspx`. IIS requests show command-like query values including `cmd=whoami`, `cmd=ipconfig`, `cmd=net%20user`, `cmd=net%20localgroup%20administrators`, `cmd=dir%20C:\Users`, and `cmd=systeminfo`.

**Interpretation:** An unexpected `.aspx` file in this location paired with command-like parameters is highly suspicious. Confirm the file hash, creation time, content, owner/ACL, and whether the application legitimately uses the path.

### A5. IIS worker spawning commands
Process telemetry shows `w3wp.exe` associated with `cmd.exe` commands for system discovery. This is a strong web-shell/exploitation indicator in context. `csc.exe` may be legitimate ASP.NET compilation, so review its path, command line, timing, and neighboring events rather than classifying it alone.

### Preliminary chain A
1. Concentrated 404 responses.
2. Broad URI discovery.
3. POST references a shell filename.
4. File-create event records a suspicious `.aspx` path.
5. HTTP requests pass command-like parameters.
6. `w3wp.exe` spawns `cmd.exe` for discovery.

This chain is plausible from the screenshots, but validate host identity, normalized timestamps, and raw events before calling it a confirmed incident chain.

## Evidence stream B — OWA credential activity

### B1. Repeated authentication requests
Screenshots show repeated requests to `/owa/auth.owa` and `/owa/auth/logon.aspx`, including **16 POST requests in a five-minute bucket** for the captured source. A redirect example contains `reason=2`.

**Interpretation:** Repeated POSTs from one source can indicate brute force or repeated login attempts. Confirm the meaning of `reason=2` for the Exchange version and log format.

### B2. Windows Security events
The displayed 4625 summary includes `sarah.kim` (15 events, Logon Type 8), `david.chen` (10, Type 3), `liam.patel` (1, Type 3), and `michelle.smith` (1, Type 3). These are screenshot observations, not a full account report. Verify the raw event fields and source hosts.

### B3. Chronology caveat
In the displayed `sarah.kim` timeline, a 4624 event at `2026-02-12 10:29:32` precedes a cluster of 4625 events beginning around `10:40`. This is **not** evidence of a failed-login burst followed by success. It may be a successful session followed by later failures, or different activity requiring context.

A separate comparison screenshot shows OWA activity and a 4624 event for `michelle.smith` on `2026-02-13`. Do not assume it belongs to the earlier Sarah Kim activity without matching host, source, and time.

### Questions to answer
- Do repeated POSTs come from one source or a proxy/load balancer?
- Were attempts against one account or spread across many accounts?
- Does `reason=2` consistently mean failed authentication in this environment?
- Are 4624/4625 events from Exchange, a domain controller, or another host?
- Did any successful session access ECP/PowerShell or perform unusual mailbox activity?

## Assessing domain impact
The screenshots do not yet prove domain-wide compromise. Investigate DC authentication events (4768, 4769, 4771, 4776), privileged-group changes (4728/4732/4756 where applicable), new accounts/account changes (4720/4722/4724/4738), remote logons, scheduled tasks, services, PowerShell, WMI, lateral movement, and access to file/SQL servers.

## Confidence and limitations
| Claim | Confidence | Caveat |
|---|---|---|
| Captured IIS search shows 114 404s from one IP | High for screenshot observation | Not a full dataset export |
| Suspicious `.aspx` endpoint was requested | High for screenshot observation | Confirm raw requests and host |
| Command-like query strings were present | High for screenshot observation | Confirm decoded values and chronology |
| `w3wp.exe` spawned command-shell activity | High for screenshot observation | Validate process source and host |
| `203.0.113.47` is a real attacker | Not supported | Documentation-only address range |
| OWA and web-shell evidence are one incident | Unconfirmed | Need host/time/source correlation |
| Successful login followed failure burst | Not supported by shown timeline | Visible 4624 precedes later 4625 cluster |
| Domain-wide compromise occurred | Unconfirmed | Need DC and internal-host telemetry |

## Next actions
1. Export raw IIS, Sysmon, and Security events from the same host and bounded time window.
2. Normalize IIS UTC and Windows event times.
3. Verify upload, file creation, shell requests, and process ancestry.
4. Review the upload handler, file hash, file metadata, and ACLs.
5. Correlate OWA requests with the correct Exchange host and authentication events.
6. Scope DC and internal-host activity after any suspicious session.
7. Document benign explanations, telemetry gaps, and confidence.


## Evidence stream C — VPN credential activity via RADIUS / NPS

### C1. Authentication architecture
The supplied diagram shows a user connecting through a VPN gateway, which forwards authentication via RADIUS to Windows Network Policy Server (NPS), followed by LDAP communication with the domain controller. NPS events are expected only when the gateway is configured to use RADIUS/NPS. Confirm the actual authentication architecture before interpreting missing NPS events.

### C2. NPS denial distribution
The captured `index=win EventCode=6273 | stats count by User_Account_Name, Client_IP_Address` result shows 12 denial events: `david.chen` has 10, `liam.patel` has 1, and `michelle.smith` has 1. All three are grouped under `Client_IP_Address=10.5.10.200`. This makes David Chen the strongest account lead in this result set, but repeated failures can also result from mistyped/saved credentials or misconfigured clients. Confirm time range, raw reason codes, and the identity of the RADIUS client. The client IP is not necessarily the remote user's original IP.

### C3. Windows authentication sequence
A separate screenshot shows ten Event ID 4625 records for `david.chen` on `THM-DC` from about `10:46:01` to `10:47:00` on `2026-02-12`, followed by Event ID 4624 at about `10:47:05`, with displayed Logon Type 3. This failure cluster followed by success is consistent with a possible credential attack and merits priority review. It is not proof that these are the same attempts seen in NPS; correlate raw timestamps, host, account, source/gateway, status/substatus, and authentication package.

### C4. NPS field-mapping caveat
A separate search of NPS 6272/6273 events filtered by `User_Account_Name=david.chen` displays dash/blank account fields, including on a row with EventCode 6272. This may indicate inconsistent extraction or a mismatched field/filter. Do not claim a verified NPS success for David based on that row. Re-run without the account filter and inspect raw events.

### C5. Event references and next pivots
The supplied notes identify NPS Event ID 6272 as granted access, 6273 as denied access, and 6274 as discarded request. They describe reason codes 16 (unknown user/bad password), 48 (no matching network policy), and 65 (RADIUS shared-secret mismatch); validate these against raw events and the installed version. Follow up with Windows 4624/4625 details, Event ID 4776 for NTLM credential validation when applicable, Kerberos events 4768/4769/4771, and post-authentication activity.

**Assessment:** The VPN path is a separate high-priority credential-attack lead. The screenshot supports a Windows failed-logon cluster followed by success, while the direct NPS-to-Windows correlation remains unconfirmed because the displayed NPS account field is inconsistent. Keep this path separate from the IIS web-shell and OWA paths until evidence links them. See `vpn-radius-nps-investigation.md` and the new SPL queries for detailed steps.


## Evidence stream C — Separate IIS `error.aspx` scenario

A later evidence batch describes a distinct source and filename from stream A. The screenshots show 21 IIS 404 events for `198.51.100.23`; nine successful responses from that source, including five to `/aspnet_client/system_web/error.aspx` and two to `/internalapp/upload.aspx`; GET requests to `error.aspx` with command-like query values (`hostname`, `tasklist`, `netstat -an`, directory listing, and domain-group enumeration); a POST to `/internalapp/upload.aspx` with `file=error.aspx`; and a Sysmon Event ID 11 screenshot matching `error.aspx` on `THM-WEB-SRV.tryhatmestudios.thm`.

This is suspicious and warrants correlation, but does not alone prove the commands executed or that the POST created the file. Validate raw IIS/Sysmon events, full target path, exact timestamps, and process creation. `198.51.100.23` is a documentation-range address. Keep this stream separate from the earlier `shell.aspx` / `203.0.113.47` sequence unless correlation proves a relationship. Full workflow and SPL are in `01-investigation-notes/iis-error-aspx-threat-hunting-scenario.md` and query files `20`–`24`.
