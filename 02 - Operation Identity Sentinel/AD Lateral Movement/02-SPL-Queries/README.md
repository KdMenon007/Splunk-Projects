# SPL Query Library — AD Lateral Movement

Queries are grouped by investigative pivot. Run them against the lab's actual index and field names; replace example hosts, IPs, and Logon IDs as needed.

- `01`–`02`: AD discovery (Sysmon Event 1 / PowerShell 4104)
- `03`–`07`: explicit credentials, admin-share access, source mapping, and baseline context
- `08`–`12`: PsExec/service-install, child-process, named-pipe, detailed-share, and source execution evidence
- `13`–`18`: RDP chaining from DC process discovery through Logon ID correlation, source-host mapping, and `mstsc.exe`
- `19`–`23`: `svcupdate` challenge evidence and source-host correlation

**Field caveat:** Lab screenshots use variants such as `LogonId` and `Logon_ID`, `Source_Network_Address` and `Source_Address`, and `service_path`. Confirm the field names in your own events. Event 5140/5145 require the relevant audit policies. Correlate multiple artifacts rather than treating a single event as proof of malicious activity.
