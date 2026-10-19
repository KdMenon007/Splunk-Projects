# Splunk SOC Investigation — MITRE ATT&CK Technique-Wise Cheat Sheet

**Framework:** MITRE ATT&CK Enterprise v19.1  
**Focus:** Splunk SPL + CIM + Windows Event Logs + endpoint/network telemetry  
**Purpose:** technique-first SOC investigation and defensive detection engineering.

Splunk Security Content currently publishes a large detection library mapped to MITRE ATT&CK, with detections, analytic stories, searches, and coverage information.

## How to use this book

`ALERT → ATT&CK TECHNIQUE → IOC → TIME → USER → SOURCE IP → HOST → PROCESS → PARENT → COMMAND LINE → NETWORK → DNS → OTHER HOSTS → PERSISTENCE → LATERAL MOVEMENT → C2 → EXFIL/IMPACT`

Every technique entry contains:
- **Technique ID / name**
- **SPL starting search**
- **Investigation pivot**
- **Sub-techniques**

Queries are starting points. Validate your field names, CIM normalization, sourcetypes, thresholds, and telemetry before production use.

## TA0001 — Initial Access

### T1566 — Phishing

**SPL starting query**
```spl
index=* (sourcetype=*mail* OR sourcetype=*o365* OR sourcetype=*exchange*)
| search subject=* OR sender=* OR attachment=* OR url=*
| table _time user sender recipient subject attachment url
```

**Investigation:** Start with sender → recipient → attachment/link → endpoint process → network destination.

**Sub-techniques / scope:** T1566.001 Attachment; T1566.002 Spearphishing Link; T1566.003 Spearphishing via Service

### T1190 — Exploit Public-Facing Application

**SPL starting query**
```spl
index=web
(http_status>=400 OR uri IN ("*../*","*UNION SELECT*","*cmd=*"))
| stats count by src_ip dest host uri http_status
| sort -count
```

**Investigation:** Pivot from exploit request → server host → process creation → persistence.

**Sub-techniques / scope:** T1190

### T1133 — External Remote Services

**SPL starting query**
```spl
index=auth
(action=success OR EventCode=4624)
(service=vpn OR service=rdp OR service=ssh OR Logon_Type=10)
| stats count by user src_ip dest host
```

**Investigation:** Investigate successful external access, especially first-seen IPs and failures immediately before success.

**Sub-techniques / scope:** T1133

### T1078 — Valid Accounts

**SPL starting query**
```spl
index=auth action=success
| stats count dc(src_ip) as src_ips dc(dest) as hosts values(src_ip) as ips by user
| where src_ips>3 OR hosts>5
```

**Investigation:** Baseline account-to-IP/host relationships; unusual successful use is the key pivot.

**Sub-techniques / scope:** T1078.001 Default Accounts; T1078.002 Domain Accounts; T1078.003 Local Accounts; T1078.004 Cloud Accounts

## TA0002 — Execution

### T1059 — Command and Scripting Interpreter

**SPL starting query**
```spl
index=endpoint
(process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","bash","sh","python*"))
| table _time host user parent_process_name process_name process_path command_line
```

**Investigation:** Pivot process → parent → command line → user → network.

**Sub-techniques / scope:** T1059.001 PowerShell; T1059.003 Windows Command Shell; T1059.004 Unix Shell; T1059.005 Visual Basic; T1059.006 Python

### T1204 — User Execution

**SPL starting query**
```spl
index=endpoint
(parent_process_name IN ("winword.exe","excel.exe","outlook.exe","acrord32.exe"))
(process_name IN ("powershell.exe","cmd.exe","wscript.exe","mshta.exe"))
| table _time host user parent_process_name process_name command_line
```

**Investigation:** Office/document/browser spawning a shell is a high-value execution chain.

**Sub-techniques / scope:** T1204.002 Malicious File; T1204.001 Malicious Link

### T1106 — Native API

**SPL starting query**
```spl
index=endpoint
(command_line="*CreateRemoteThread*" OR command_line="*VirtualAllocEx*" OR command_line="*WriteProcessMemory*")
| table _time host user process_name command_line
```

**Investigation:** Use as supporting evidence for injection; endpoint telemetry is stronger than string matching.

**Sub-techniques / scope:** T1106

### T1129 — Shared Modules

**SPL starting query**
```spl
index=endpoint
(process_name IN ("rundll32.exe","regsvr32.exe") OR command_line="*.dll*")
| table _time host user parent_process_name process_name command_line
```

**Investigation:** Investigate unusual DLL loading/registration and ancestry.

**Sub-techniques / scope:** T1129

## TA0003 — Persistence

### T1053 — Scheduled Task/Job

**SPL starting query**
```spl
index=windows
(EventCode=4698 OR command_line="*schtasks*" OR command_line="*cron*")
| table _time host user Task_Name command_line
```

**Investigation:** New task + unusual creator + suspicious executable is high priority.

**Sub-techniques / scope:** T1053.005 Scheduled Task; T1053.003 Cron

### T1543 — Create or Modify System Process

**SPL starting query**
```spl
index=windows
(EventCode=7045 OR command_line="*sc.exe create*" OR command_line="*systemctl enable*")
| table _time host user service_name ImagePath command_line
```

**Investigation:** Pivot service → binary → creator → first execution → network.

**Sub-techniques / scope:** T1543.003 Windows Service; T1543.002 Systemd Service

### T1547 — Boot or Logon Autostart

**SPL starting query**
```spl
index=endpoint
(registry_path="*\\CurrentVersion\\Run*" OR registry_path="*\\RunOnce*" OR file_path="*Startup*")
| table _time host user registry_path registry_value file_path process_name
```

**Investigation:** Investigate persistence changes followed by execution.

**Sub-techniques / scope:** T1547.001 Registry Run Keys/Startup Folder; T1547.004 Winlogon Helper DLL

### T1136 — Create Account

**SPL starting query**
```spl
index=windows
(EventCode=4720 OR command_line="*net user* /add*" OR command_line="*useradd*")
| table _time host user TargetUserName command_line
```

**Investigation:** Pivot new account → group membership → first login → actions.

**Sub-techniques / scope:** T1136.001 Local Account; T1136.002 Domain Account; T1136.003 Cloud Account

### T1505.003 — Web Shell

**SPL starting query**
```spl
index=web method=POST
(uri IN ("*.php","*.jsp","*.aspx"))
("cmd=" OR "exec=" OR "shell=" OR "command=")
| table _time src_ip host uri status
```

**Investigation:** Pivot request → web server process → child shell → outbound connection.

**Sub-techniques / scope:** T1505.003 Web Shell

## TA0004 — Privilege Escalation

### T1068 — Exploitation for Privilege Escalation

**SPL starting query**
```spl
index=endpoint
| search (process_name=* OR command_line=*)
| table _time host user process_name parent_process_name command_line
```

**Investigation:** Look for an exploit indicator followed by a privilege/integrity change.

**Sub-techniques / scope:** T1068

### T1548 — Abuse Elevation Control Mechanism

**SPL starting query**
```spl
index=endpoint
(command_line="*runas*" OR command_line="*fodhelper*" OR command_line="*eventvwr*" OR command_line="*sudo*")
| table _time host user parent_process_name process_name command_line
```

**Investigation:** Investigate elevation utility, parent, integrity level, and subsequent privileged process.

**Sub-techniques / scope:** T1548.002 Bypass UAC; T1548.003 Sudo

### T1134 — Access Token Manipulation

**SPL starting query**
```spl
index=endpoint
(command_line="*token*" OR command_line="*impersonat*")
| table _time host user process_name command_line
```

**Investigation:** Supporting hunt for token theft/impersonation; correlate with privileged actions.

**Sub-techniques / scope:** T1134.001 Token Impersonation/Theft; T1134.002 Create Process with Token

## TA0005 — Defense Evasion / TA0006 — Credential Access

### T1562 — Impair Defenses

**SPL starting query**
```spl
index=endpoint
(command_line="*Set-MpPreference*" OR command_line="*DisableRealtimeMonitoring*" OR command_line="*auditpol*" OR command_line="*wevtutil*")
| table _time host user process_name command_line
```

**Investigation:** Correlate defense impairment with suspicious execution before/after.

**Sub-techniques / scope:** T1562.001 Disable or Modify Tools; T1562.002 Disable Windows Event Logging

### T1070 — Indicator Removal

**SPL starting query**
```spl
index=windows
(EventCode=1102 OR command_line="*wevtutil cl*" OR command_line="*del /f*" OR command_line="*rm -f*")
| table _time host user src_ip command_line
```

**Investigation:** Cleared logs/deletion are stronger when preceded by suspicious execution.

**Sub-techniques / scope:** T1070.001 Clear Windows Event Logs; T1070.004 File Deletion

### T1055 — Process Injection

**SPL starting query**
```spl
index=endpoint
(command_line="*CreateRemoteThread*" OR command_line="*WriteProcessMemory*" OR command_line="*VirtualAllocEx*")
| table _time host user process_name parent_process_name command_line
```

**Investigation:** Treat command-line matches as leads; EDR injection telemetry is preferable.

**Sub-techniques / scope:** T1055.001 DLL Injection; T1055.012 Process Hollowing

### T1003 — OS Credential Dumping

**SPL starting query**
```spl
index=endpoint
(command_line="*sekurlsa*" OR command_line="*mimikatz*" OR command_line="*procdump*" OR command_line="*nanodump*" OR command_line="*lsass*")
| table _time host user process_name parent_process_name command_line
```

**Investigation:** Immediately pivot to LSASS access → privileges → credentials → subsequent logons.

**Sub-techniques / scope:** T1003.001 LSASS Memory; T1003.002 SAM; T1003.003 NTDS

### T1558 — Steal or Forge Kerberos Tickets

**SPL starting query**
```spl
index=windows
EventCode IN (4768,4769,4771)
| stats count by user src_ip host Service_Name TicketEncryptionType
| sort -count
```

**Investigation:** Investigate unusual ticket volume, encryption, service accounts, and source hosts.

**Sub-techniques / scope:** T1558.001 Golden Ticket; T1558.002 Silver Ticket; T1558.003 Kerberoasting; T1558.004 AS-REP Roasting

### T1552 — Unsecured Credentials

**SPL starting query**
```spl
index=endpoint
(file_path="*password*" OR file_path="*credentials*" OR file_path="*web.config*" OR file_path="*.kdbx" OR file_path="*.pem")
| table _time host user process_name file_path
```

**Investigation:** Pivot credential file access → process → account → subsequent authentication.

**Sub-techniques / scope:** T1552.001 Credentials In Files; T1552.004 Private Keys

### T1110 — Brute Force

**SPL starting query**
```spl
index=windows EventCode=4625
| stats count as failures dc(user) as unique_users by src_ip
| where failures>=20 OR unique_users>=10
| sort -failures
```

**Investigation:** Differentiate password spraying (many users) from brute force (one/few users).

**Sub-techniques / scope:** T1110.001 Password Guessing; T1110.003 Password Spraying; T1110.004 Credential Stuffing

## TA0007 — Discovery

### T1087 — Account Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*net user*" OR command_line="*Get-LocalUser*" OR command_line="*Get-ADUser*")
| table _time host user process_name command_line
```

**Investigation:** Look for enumeration bursts and unusual users performing AD reconnaissance.

**Sub-techniques / scope:** T1087.001 Local Account; T1087.002 Domain Account

### T1069 — Permission Groups Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*net localgroup*" OR command_line="*net group*" OR command_line="*Get-LocalGroup*" OR command_line="*Get-ADGroup*")
| table _time host user process_name command_line
```

**Investigation:** Group discovery often precedes privilege escalation or lateral movement.

**Sub-techniques / scope:** T1069.001 Local Groups; T1069.002 Domain Groups

### T1016 — System Network Configuration Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*ipconfig*" OR command_line="*Get-NetIPConfiguration*" OR command_line="*ifconfig*")
| table _time host user process_name command_line
```

**Investigation:** Correlate with other discovery and scanning commands.

**Sub-techniques / scope:** T1016

### T1049 — System Network Connections Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*netstat*" OR command_line="*Get-NetTCPConnection*" OR command_line="*ss -*" OR command_line="*lsof -i*")
| table _time host user process_name command_line
```

**Investigation:** Look for endpoint connection enumeration before C2/lateral movement.

**Sub-techniques / scope:** T1049

### T1057 — Process Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*tasklist*" OR command_line="*Get-Process*" OR command_line="*ps -ef*")
| table _time host user process_name command_line
```

**Investigation:** Process discovery followed by LSASS/injection is particularly interesting.

**Sub-techniques / scope:** T1057

### T1082 — System Information Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*systeminfo*" OR command_line="*hostname*" OR command_line="*uname*" OR command_line="*Get-ComputerInfo*")
| table _time host user process_name command_line
```

**Investigation:** Use burst behavior and host/user baselines.

**Sub-techniques / scope:** T1082

### T1046 — Network Service Scanning

**SPL starting query**
```spl
index=firewall OR index=network
| stats dc(dest_ip) as hosts dc(dest_port) as ports by src_ip
| where hosts>50 OR ports>20
| sort -hosts
```

**Investigation:** Source touching many destinations/ports is a scan candidate.

**Sub-techniques / scope:** T1046

### T1482 — Domain Trust Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*nltest*" OR command_line="*Get-ADTrust*" OR command_line="*netdom*")
| table _time host user process_name command_line
```

**Investigation:** Useful precursor to domain/forest lateral movement.

**Sub-techniques / scope:** T1482

### T1018 — Remote System Discovery

**SPL starting query**
```spl
index=endpoint
(command_line="*net view*" OR command_line="*Get-ADComputer*" OR command_line="*arp*")
| table _time host user process_name command_line
```

**Investigation:** Pivot discovery → authentication → remote execution.

**Sub-techniques / scope:** T1018

## TA0008 — Lateral Movement

### T1021 — Remote Services

**SPL starting query**
```spl
index=windows
(EventCode=4624 OR EventCode=5140 OR EventCode=5145)
| stats count by user src_ip host Logon_Type Share_Name
| sort -count
```

**Investigation:** Pivot source → destination → identity → post-login process.

**Sub-techniques / scope:** T1021.001 RDP; T1021.002 SMB/Windows Admin Shares; T1021.004 SSH; T1021.006 WinRM

### T1047 — Windows Management Instrumentation

**SPL starting query**
```spl
index=endpoint
(process_name IN ("wmic.exe","WmiPrvSE.exe") OR command_line="*wmic*")
| table _time host user src_ip parent_process_name process_name command_line
```

**Investigation:** WMI is dual-use; prioritize remote execution and unusual ancestry.

**Sub-techniques / scope:** T1047

### T1563 — Remote Service Session Hijacking

**SPL starting query**
```spl
index=windows EventCode=4624
| search Logon_Type=10
| table _time host user src_ip
```

**Investigation:** Look for unusual remote-session reuse or RDP anomalies.

**Sub-techniques / scope:** T1563.002 RDP Hijacking

### T1550 — Use Alternate Authentication Material

**SPL starting query**
```spl
index=windows
(EventCode=4624 OR EventCode=4769)
| stats count by user src_ip host Logon_Type
| sort -count
```

**Investigation:** Use authentication context and unusual source/host relationships to investigate pass-the-hash/ticket hypotheses.

**Sub-techniques / scope:** T1550.002 Pass the Hash; T1550.003 Pass the Ticket

## TA0009 — Collection

### T1114 — Email Collection

**SPL starting query**
```spl
index=email
| stats count by user action src_ip
| sort -count
```

**Investigation:** Investigate unusual mailbox access, forwarding, and bulk retrieval.

**Sub-techniques / scope:** T1114.001 Local Email Collection; T1114.002 Remote Email Collection; T1114.003 Email Forwarding Rule

### T1005 — Data from Local System

**SPL starting query**
```spl
index=endpoint
(file_path=* OR file_name=*)
| stats count by host user file_extension
| sort -count
```

**Investigation:** Look for unusual file access volume and staging behavior.

**Sub-techniques / scope:** T1005

### T1213 — Data from Information Repositories

**SPL starting query**
```spl
index=proxy OR index=web OR index=database
| stats count by user dest uri
| sort -count
```

**Investigation:** Investigate unusual access to repositories, shares, databases, and business apps.

**Sub-techniques / scope:** T1213.002 SharePoint; T1213.003 Code Repositories

### T1074 — Data Staged

**SPL starting query**
```spl
index=endpoint
(process_name IN ("7z.exe","7za.exe","rar.exe","tar.exe") OR command_line="*Compress-Archive*")
| table _time host user process_name command_line
```

**Investigation:** Archive/staging behavior is more suspicious when followed by outbound transfer.

**Sub-techniques / scope:** T1074.001 Local Data Staging; T1074.002 Remote Data Staging

### T1560 — Archive Collected Data

**SPL starting query**
```spl
index=endpoint
(process_name IN ("7z.exe","7za.exe","rar.exe","tar.exe") OR command_line="*Compress-Archive*")
| stats count by host user process_name
| sort -count
```

**Investigation:** Prioritize unusual user/host, high archive volume, and archive movement.

**Sub-techniques / scope:** T1560.001 Archive via Utility; T1560.002 Archive via Library

## TA0011 — Command and Control

### T1071 — Application Layer Protocol

**SPL starting query**
```spl
index=network OR index=proxy
(dest_port IN (80,443,53,25,587) OR protocol IN ("http","https","dns","smtp"))
| stats count by src_ip dest_ip dest_port
| sort -count
```

**Investigation:** Look for rare destinations, periodicity, user-agent anomalies, and endpoint ancestry.

**Sub-techniques / scope:** T1071.001 Web Protocols; T1071.004 DNS

### T1095 — Non-Application Layer Protocol

**SPL starting query**
```spl
index=firewall
| stats count by src_ip dest_ip dest_port protocol
| sort -count
```

**Investigation:** Investigate uncommon protocols/ports generated by endpoints.

**Sub-techniques / scope:** T1095

### T1105 — Ingress Tool Transfer

**SPL starting query**
```spl
index=proxy OR index=network
(action=download OR http_method=GET OR uri="*")
| stats count by src_ip dest_ip uri
| sort -count
```

**Investigation:** Pivot download → file/hash → execution → parent → outbound network.

**Sub-techniques / scope:** T1105

### T1573 — Encrypted Channel

**SPL starting query**
```spl
index=network
| stats count by src_ip dest_ip dest_port
| sort -count
```

**Investigation:** Encrypted traffic is normal; combine rarity, periodicity, and destination context.

**Sub-techniques / scope:** T1573.001 Symmetric Cryptography; T1573.002 Asymmetric Cryptography

### T1219 — Remote Access Software

**SPL starting query**
```spl
index=endpoint
process_name IN ("anydesk.exe","teamviewer.exe","screenconnect.exe","rustdesk.exe")
| table _time host user process_name process_path command_line
```

**Investigation:** Investigate first-seen installation/execution and external connections.

**Sub-techniques / scope:** T1219

### T1102 — Web Service

**SPL starting query**
```spl
index=proxy
(dest_domain="*pastebin*" OR dest_domain="*discord*" OR dest_domain="*telegram*" OR dest_domain="*github*")
| stats count by src_ip dest_domain uri
| sort -count
```

**Investigation:** Service matches are pivots, not verdicts; correlate process, user, and timing.

**Sub-techniques / scope:** T1102.002 Bidirectional Communication

## TA0010 — Exfiltration

### T1041 — Exfiltration Over C2 Channel

**SPL starting query**
```spl
index=firewall
| stats sum(bytes_out) as bytes_out by src_ip dest_ip
| where bytes_out>100000000
| sort -bytes_out
```

**Investigation:** Find high-volume outbound transfers to suspicious or rare destinations.

**Sub-techniques / scope:** T1041

### T1567 — Exfiltration Over Web Service

**SPL starting query**
```spl
index=proxy
method=POST
| stats sum(bytes_out) as bytes_out by user src_ip dest_domain
| where bytes_out>100000000
| sort -bytes_out
```

**Investigation:** Investigate large uploads to uncommon cloud/file-sharing services.

**Sub-techniques / scope:** T1567.002 Exfiltration to Cloud Storage

### T1048 — Exfiltration Over Alternative Protocol

**SPL starting query**
```spl
index=firewall
| stats sum(bytes_out) as bytes_out by src_ip dest_port protocol
| where bytes_out>100000000
| sort -bytes_out
```

**Investigation:** Look for abnormal outbound protocols/ports relative to host baseline.

**Sub-techniques / scope:** T1048

### T1029 — Scheduled Transfer

**SPL starting query**
```spl
index=firewall
| bin _time span=5m
| stats sum(bytes_out) as bytes_out by _time src_ip dest_ip
| sort 0 src_ip dest_ip _time
```

**Investigation:** Repeated transfers at regular intervals can support an exfiltration hypothesis.

**Sub-techniques / scope:** T1029

## TA0040 — Impact

### T1486 — Data Encrypted for Impact

**SPL starting query**
```spl
index=endpoint
(command_line="*vssadmin*delete shadows*" OR command_line="*wbadmin*delete*" OR command_line="*encrypt*")
| table _time host user process_name parent_process_name command_line
```

**Investigation:** Correlate backup destruction, mass file changes, ransom notes, and process ancestry.

**Sub-techniques / scope:** T1486

### T1490 — Inhibit System Recovery

**SPL starting query**
```spl
index=endpoint
(command_line="*vssadmin*delete shadows*" OR command_line="*wbadmin*delete*" OR command_line="*bcdedit*")
| table _time host user process_name command_line
```

**Investigation:** High priority when combined with mass file modification.

**Sub-techniques / scope:** T1490

### T1489 — Service Stop

**SPL starting query**
```spl
index=endpoint
(command_line="*net stop*" OR command_line="*sc stop*" OR command_line="*Stop-Service*")
| table _time host user process_name command_line
```

**Investigation:** Look specifically for security, backup, database, and endpoint protection services.

**Sub-techniques / scope:** T1489

### T1496 — Resource Hijacking

**SPL starting query**
```spl
index=endpoint
(process_name IN ("xmrig","minerd","cpuminer") OR command_line="*stratum*")
| table _time host user process_name command_line
```

**Investigation:** Unexpected mining processes plus sustained CPU/network activity are strong candidates.

**Sub-techniques / scope:** T1496

## Reusable Correlation Queries

### Failed logons → successful logon
```spl
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures
        count(eval(EventCode=4624)) as successes
        earliest(_time) as first_seen latest(_time) as last_seen
        by user src_ip
| where failures>=5 AND successes>0
| sort -failures
```

### IOC universal pivot
```spl
index=* earliest=-7d ("IOC")
| sort 0 _time
| table _time index sourcetype host user src_ip dest_ip process_name parent_process_name command_line uri
```

### Entity profile
```spl
index=* user="USER" earliest=-30d
| stats earliest(_time) as first_seen latest(_time) as last_seen count
        values(src_ip) as src_ips
        values(dest_ip) as dest_ips
        values(host) as hosts
        values(process_name) as processes
        by user
```

### Host profile
```spl
index=* host="HOST" earliest=-30d
| stats earliest(_time) as first_seen latest(_time) as last_seen count
        values(user) as users
        values(src_ip) as src_ips
        values(dest_ip) as destinations
        values(process_name) as processes
        by host
```

### Technique-chain timeline
```spl
index=* host="HOST" earliest=-2h latest=now
| sort 0 _time
| table _time sourcetype user src_ip dest_ip process_name parent_process_name command_line action EventCode
```

### MITRE coverage query
```spl
| inputlookup detections.csv
| search mitre_attack_technique_id="T1059.001"
| table name mitre_attack_technique_id data_source type analytic_story
```

## Splunk fields worth memorizing

| Area | Common CIM / investigation fields |
|---|---|
| Identity | `user`, `src_user`, `dest_user` |
| Host | `dest`, `src`, `host`, `dvc` |
| Network | `src`, `dest`, `src_ip`, `dest_ip`, `src_port`, `dest_port`, `bytes_out` |
| Process | `process_name`, `parent_process_name`, `process_path`, `command_line` |
| Authentication | `action`, `Logon_Type`, `EventCode`, `src_ip`, `user` |
| Web | `uri`, `url`, `http_method`, `status`, `user_agent`, `src_ip` |
| DNS | `query`, `src_ip`, `record_type`, `answer` |
| File | `file_name`, `file_path`, `file_hash`, `file_extension` |
| Cloud | provider-specific fields + normalized `user`, `src`, `dest`, `action` |

## Detection engineering rules

1. **Technique ≠ verdict.** PowerShell, RDP, WMI, `net user`, and service creation are legitimate in many environments.
2. Prefer **behavior chains** over isolated keywords.
3. Always identify the **data source** that gives you confidence.
4. Use CIM/data models when available; use `tstats` for high-volume accelerated data models.
5. Keep MITRE IDs in detection metadata and names.
6. Measure **data availability + active detection + false positives**, not merely ATT&CK matrix color.
7. A detection is only as good as the environment it actually monitors.

## Recommended detection naming

`[T1059.001] PowerShell — Encoded Command`

`[T1110.003] Password Spraying — Many Users / Source`

`[T1021.001] RDP — Unusual Successful Remote Logon`

`[T1003.001] LSASS Memory — Suspicious Access`

## References

Splunk Security Content: https://research.splunk.com/

Splunk detections: https://research.splunk.com/detections/

Splunk Security Content GitHub: https://github.com/splunk/security_content

Splunk MITRE ATT&CK guidance: https://www.splunk.com/en_us/blog/security/using-mitre-att-ck-in-splunk-security-essentials.html

MITRE ATT&CK: https://attack.mitre.org/
