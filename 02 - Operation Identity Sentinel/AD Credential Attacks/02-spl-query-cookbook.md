# SPL Query Cookbook — AD Credential Attacks

| Detection | Telemetry | Main signal | Caveat |
|---|---|---|---|
| Kerberoasting | Event 4769, `task2` | RC4 tickets for multiple service accounts or burst of unique SPNs | RC4 can be legitimate; AES-based attacks exist |
| AS-REP Roasting | Event 4768, `task3` | `Pre_Authentication_Type=0` | Confirm account configuration and source context |
| LSASS access | Sysmon Event 10, `task4` | Unexpected process access to `lsass.exe` | Requires appropriate ProcessAccess collection |

- `sort - count` sorts numeric counts descending.
- `sort _time` sorts chronologically; `sort_time` is not a standard SPL command.
- `dc(Service_Name)` counts distinct service names.
- Tune thresholds against a normal baseline and validate custom field names before operational use.
