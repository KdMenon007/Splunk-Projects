# Threat-Hunting Scenario — IIS `error.aspx` Web-Shell Investigation

## Scenario scope
This is a **separate IIS web-shell example** based on the newly supplied screenshots. Do not merge it with the earlier `shell.aspx` / `203.0.113.47` evidence stream unless raw events establish matching host, time, and source context. This scenario uses source `198.51.100.23` and the endpoint `error.aspx`; the address is in TEST-NET-2 and should be treated as sanitized documentation/lab data, not real attribution.

**Objective:** Follow a simple evidence-led chain from repeated IIS 404 responses, to successful requests from one source, to command-like query parameters, an upload endpoint, and a Windows/Sysmon file-create event.

## Step 1 — Identify the source associated with repeated 404s

```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

**Screenshot observation:** The supplied result shows 21 events for `198.51.100.23`.

**Interpretation:** Concentrated 404 responses may indicate path enumeration or scanning. They can also arise from scanners, crawlers, broken links, or application errors. Treat this as a lead, not proof of compromise.

## Step 2 — Inspect successful requests from that source

```spl
index=iis c_ip="198.51.100.23" sc_status=200
| stats count by cs_uri_stem
| sort - count
```

**Screenshot observation:** The supplied result shows nine events. `/aspnet_client/system_web/error.aspx` appears five times, `/internalapp/upload.aspx` twice, `/internalapp/` once, and `/internalapp/default.aspx` once.

**Interpretation:** An unexpected ASP.NET endpoint with repeated successful responses deserves investigation. HTTP 200 means a successful HTTP response, not necessarily successful exploitation or command execution.

## Step 3 — Review requests to `error.aspx` and their parameters

```spl
index=iis cs_uri_stem="*/error.aspx"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

The screenshot shows GET requests with command-like query values including `cmd=hostname`, `cmd=tasklist`, `cmd=netstat%20-an`, a directory listing request, and a domain-group enumeration request. These are consistent with host and domain reconnaissance if confirmed in raw events. Query-string values should be URL-decoded before interpretation.

## Step 4 — Find the upload-related request

```spl
index=iis cs_method=POST cs_uri_query="*error.aspx*"
| table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
| sort _time
```

The screenshot shows one POST to `/internalapp/upload.aspx`, with query `file=error.aspx` and status 200. This supports an upload-related lead, but a 200 response alone does not prove a file was written. Confirm the handler's behavior and correlate with file-system telemetry.

## Step 5 — Correlate file creation in Windows/Sysmon

```spl
index=win EventCode=11 TargetFilename="*error.aspx"
| table _time, host, ComputerName, Image, TargetFilename, EventCode
| sort _time
```

The supplied screenshot shows a Sysmon Event ID 11 event on `THM-WEB-SRV.tryhatmestudios.thm` with `TargetFilename` matching `error.aspx`. Verify the full target path in the raw event and align its timestamp with the IIS POST and later requests. If `TargetFilename` is not extracted, inspect the raw event and use the actual field name.

## Preliminary chain
1. 21 captured 404 events from `198.51.100.23`.
2. Successful responses include repeated requests to `/aspnet_client/system_web/error.aspx` and the upload endpoint.
3. Requests to `error.aspx` carry command-like parameters that resemble host/domain discovery.
4. A POST references `error.aspx` at `/internalapp/upload.aspx`.
5. A Sysmon Event ID 11 screenshot shows a file-create event matching `error.aspx` on the web server.

**Assessment:** This is a high-priority suspicious sequence in the supplied lab screenshots, but not yet a fully validated incident chain. Confirm host identity, exact file path, normalized timestamps, raw IIS and Sysmon events, and whether `w3wp.exe` spawned child processes. Do not infer that the command execution succeeded solely from query parameters or an HTTP 200 status.

## Next pivots
- Search Windows process-creation telemetry (for example, Sysmon Event ID 1) for `w3wp.exe` spawning `cmd.exe`, PowerShell, or other unexpected children.
- Inspect the file hash, contents, creation/modification times, owner and ACLs; preserve evidence before containment or deletion.
- Search all IIS requests to the file and correlate source, method, status, query, host, and timestamp.
- Determine whether the upload endpoint and `error.aspx` are expected application components.
- Normalize IIS and Windows timestamps and verify the same host and time window.
- Treat `198.51.100.23` as a documentation-range address, not a real-world attribution.

## Evidence limitations
- Counts and values are observations from the screenshots, not complete exports or guaranteed current results.
- Field names and indexes (`iis`, `win`, `c_ip`, `cs_uri_stem`, `cs_uri_query`, `TargetFilename`) are lab-specific and must be validated against raw events.
- This `error.aspx` scenario is distinct from the earlier `shell.aspx` example. Keep their timelines separate until corroborated.
