# Module status — AD Credential Attacks

Project: `02 - Operation Identity Sentinel`

| Technique | Primary telemetry | Evidence included |
|---|---|---|
| Kerberoasting | Security Event 4769 | Source notes, SPL, diagrams, result screenshot |
| AS-REP Roasting | Security Event 4768 | Source notes, SPL, diagrams, result screenshot |
| LSASS access/dumping | Sysmon Event 10 | Source notes, SPL, diagrams, result screenshot |
| DCSync | Security Event 4662 and 4624 correlation | Source notes, SPL, GUID/source-IP diagrams, query results |
| NTDS.dit extraction | Sysmon Event 1 and 11 | Source notes, SPL, extraction comparison, process/file evidence |

Status means evidence and documentation have been assembled from the supplied lab materials. It does not claim production deployment or validation outside the lab.
