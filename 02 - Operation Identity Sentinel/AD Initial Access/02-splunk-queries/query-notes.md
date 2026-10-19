# Query notes and validation

- 404 source counts identify concentrated scanning; inspect raw events and duration.
- URI pivots find unusual paths, `.aspx` endpoints, admin pages, and upload handlers.
- HTTP 200 means the server returned a 200 status, not that exploitation succeeded.
- A POST mentioning a shell filename is a lead; correlate with Sysmon file creation.
- `w3wp.exe` spawning `cmd.exe`/PowerShell with discovery commands is highly suspicious. `csc.exe` may be legitimate ASP.NET compilation.
- A 302 response does not prove OWA login success or failure. Inspect redirect parameters and corroborate with authentication events.
- A count threshold is not universal; tune to a known baseline and account for proxies/load balancers.
- Use `sort 0 _time` for complete chronological ordering.
- Field names differ between sourcetypes. Verify `user`, `User`, `Account_Name`, `src_ip`, `IpAddress`, `ParentImage`, and `Process_Name` against raw events.
- If Sysmon is indexed separately, use its actual index/sourcetype.
- Normalize IIS UTC timestamps against Windows event timestamps before correlation.
