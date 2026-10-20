# Validation Checklist

- [ ] Confirm the correct Splunk index and time range.
- [ ] Confirm Windows Security, Sysmon, and PowerShell logging coverage.
- [ ] Confirm field names and extractions (`host`, `User`/`user`, `Source_Address`, `Source_Network_Address`, `Share_Name`, `Service_Name`, `ParentImage`, `PipeName`).
- [ ] Run each query and save actual result screenshots.
- [ ] Verify whether Event 5140/5145 auditing is enabled before interpreting zero results.
- [ ] Correlate source and destination events by host, account, IP, timestamps, and session IDs where possible.
- [ ] Compare against legitimate admin activity and documented baselines.
- [ ] Redact passwords, tokens, and sensitive identifiers from public evidence.
- [ ] Add the remaining lesson notes/screenshots before marking the module complete.


## Completion checklist — RDP chaining and challenge

- [x] RDP chain concept and supplied Splunk screenshots added.
- [x] DC process `LogonId` correlated to Event 4624 / Logon Type 10.
- [x] Intermediate-host `mstsc.exe` and matching logon evidence documented.
- [x] SMB challenge includes Event 5140, Event 7045, Sysmon Event 1, and source-IP-to-machine-account correlation.
- [x] Source notes, query files, screenshots, and evidence register updated.
- [ ] Optional local validation: rerun all searches in the intended Splunk instance and compare raw events/field names.
