# AD Credential Attacks — Operation Identity Sentinel

**Project:** `02 - Operation Identity Sentinel`  
**Organization:** CatchMe Security Operations  
**Module:** AD Credential Attacks  
**Scope:** Credential-access techniques and defensive Splunk investigations only.

This package contains only the AD credential-access material: original notes, SPL query files, investigation workbook/cookbook, diagrams, and Splunk evidence screenshots. It is not part of Operation Splunk Watchtower.

## Techniques covered

1. **Kerberoasting** — Event 4769, service-ticket encryption, service-account targeting, and burst/volume detection.
2. **AS-REP Roasting** — Event 4768, `Pre_Authentication_Type=0`, and follow-up event checks.
3. **LSASS dumping/access** — Sysmon Event 10, `lsass.exe` access, process identity, access masks, and call-trace triage.
4. **DCSync** — Event 4662, replication-right GUID evidence, Logon_ID correlation to Event 4624, and source-IP investigation.
5. **NTDS.dit extraction** — Sysmon Event 1/11, `ntdsutil`, `vssadmin`, shadow-copy paths, and file-staging evidence.

## Package layout

- `source-notes/` — original supplied Markdown notes for all five techniques.
- `queries/` — paste-ready SPL queries organized by detection/investigation task.
- `screenshots/` — original credential-attack diagrams and newly supplied Splunk result screenshots.
- `01-credential-attack-investigation-workbook.md` — analyst workflow.
- `02-spl-query-cookbook.md` — query purpose and caveats.
- `evidence/evidence-register.csv` — screenshot and evidence inventory.
- `documentation/` — module status and validation notes.

## Validation and interpretation

- Indexes `task2` through `task7` are from the supplied lab notes. Confirm the index, sourcetype, field names, and time range in the active lab before reusing queries.
- RC4 (`0x17`) is not proof of Kerberoasting; AES-based Kerberoasting and legitimate RC4 use are possible.
- Event 4768 with pre-authentication type zero needs account configuration and source-context validation.
- Sysmon Event 10 requires ProcessAccess collection; absence of an event is not proof of absence of access.
- Event 4662 should be correlated with session/logon data and the expected replication baseline. The `user!="*$"` filter can miss attacks using compromised machine accounts.
- Shadow-copy creation alone can be legitimate. Correlate process execution, file creation, file paths, identity, and surrounding activity.
- The screenshots show the supplied lab's observed results, not universal thresholds or proof of malicious intent in another environment.

## Module status

**Evidence assembled for the five credential-access techniques.** Query and screenshot evidence is documented. Treat the module as lab-investigated, not as a production-validated detection pack until queries are rerun and field/index assumptions verified in the target environment.
