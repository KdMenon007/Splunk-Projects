
---
# 🛡️ SPLUNK SOC INVESTIGATION CHEAT SHEET

## 0. First: know your basic SPL

Splunk's official Search Reference is the definitive syntax reference for SPL. ([Splunk Docs](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/?utm_source=chatgpt.com "Welcome to the Search Reference - Splunk Documentation"))

### Search

```spl
index=main
```

```spl
index=windows host=WIN01
```

```spl
index=firewall src_ip=10.10.10.5
```

```spl
index=web status=500
```

### Time

```spl
earliest=-15m latest=now
```

```spl
earliest=-24h latest=now
```

```spl
earliest=-7d latest=now
```

```spl
earliest="08/16/2026:00:00:00" latest="08/16/2026:23:59:59"
```

---

# 1. The commands you will use constantly

|Command|Purpose|
|---|---|
|`search`|Filter events|
|`where`|Conditional filtering|
|`stats`|Aggregate data|
|`eventstats`|Add aggregate information back to events|
|`streamstats`|Running/previous-event calculations|
|`timechart`|Time-series analysis|
|`chart`|Cross-tabulation|
|`top`|Most common values|
|`rare`|Least common values|
|`dedup`|Remove duplicates|
|`sort`|Sort results|
|`table`|Select fields|
|`fields`|Include/exclude fields|
|`rename`|Rename fields|
|`eval`|Create/calculations|
|`rex`|Regex extraction|
|`lookup`|Enrich data|
|`join`|Correlate datasets|
|`transaction`|Group related events|
|`bin`|Time bucketing|
|`append`|Combine searches|
|`appendcols`|Add columns|
|`return`|Return values from subsearch|
|`mvexpand`|Expand multivalue fields|
|`fillnull`|Handle missing values|
|`coalesce`|Pick first non-null field|
|`tstats`|Fast indexed/data-model searches|

`stats` is especially important for investigation because it aggregates events by fields, while `tstats` can search indexed fields and accelerated data models efficiently. ([Splunk Docs](https://docs.splunk.com/Documentation/SCS/current/SearchReference/StatsCommandOverview?utm_source=chatgpt.com "stats command: Overview, syntax, and usage - Splunk Documentation"))

---

# 2. Your universal investigation template

Start with:

```spl
index=* earliest=-24h
| stats count
```

Then:

```spl
index=* earliest=-24h
| stats count by sourcetype
| sort - count
```

Then:

```spl
index=* earliest=-24h
| stats count by host
| sort - count
```

Then:

```spl
index=* earliest=-24h
| stats count by source
| sort - count
```

This tells you:

**What data do I actually have?**

---

# 3. Find fields

```spl
index=* earliest=-1h
| fieldsummary
```

Useful:

```spl
index=* earliest=-1h
| table _time host source sourcetype _raw
```

And:

```spl
index=* earliest=-1h
| stats count by host sourcetype source
```

---

# 4. Search an IP

### Find everything involving an IP

```spl
index=* "10.10.10.50" earliest=-24h
```

### Source IP

```spl
index=* src_ip="10.10.10.50"
```

### Destination IP

```spl
index=* dest_ip="10.10.10.50"
```

### Any common IP fields

```spl
index=*
(
    src_ip="10.10.10.50"
    OR dest_ip="10.10.10.50"
    OR src="10.10.10.50"
    OR dest="10.10.10.50"
    OR clientip="10.10.10.50"
)
```

### Frequency

```spl
index=*
| search src_ip="10.10.10.50"
| stats count by dest_ip dest_port
| sort -count
```

---

# 5. IP → user pivot

```spl
index=* src_ip="10.10.10.50"
| stats count values(user) as users values(host) as hosts by src_ip
```

Or:

```spl
index=*
| search src_ip="10.10.10.50"
| stats count by user
| sort -count
```

---

# 6. User investigation

When investigating:

`alice`

start with:

```spl
index=* user="alice" earliest=-24h
```

Then:

```spl
index=* user="alice"
| stats count by host
| sort -count
```

```spl
index=* user="alice"
| stats count by src_ip
| sort -count
```

```spl
index=* user="alice"
| stats count by action
| sort -count
```

```spl
index=* user="alice"
| stats earliest(_time) as first latest(_time) as last count
```

---

# 7. User → IP → host pivot

One of my favorite investigation queries:

```spl
index=*
| search user="alice"
| stats
    earliest(_time) as first_seen
    latest(_time) as last_seen
    values(src_ip) as src_ips
    values(dest_ip) as dest_ips
    values(host) as hosts
    values(action) as actions
    count
    by user
```

---

# 8. Host investigation

```spl
index=* host="WIN01"
| stats count by sourcetype
| sort -count
```

```spl
index=* host="WIN01"
| stats count by user
| sort -count
```

```spl
index=* host="WIN01"
| stats count by process_name
| sort -count
```

```spl
index=* host="WIN01"
| stats count by src_ip
| sort -count
```

---

# 9. Process investigation

Search suspicious process names:

```spl
index=* process_name=*
| stats count by process_name
| sort -count
```

Windows examples:

```spl
index=windows
(
    process_name="powershell.exe"
    OR process_name="cmd.exe"
    OR process_name="rundll32.exe"
    OR process_name="regsvr32.exe"
    OR process_name="mshta.exe"
    OR process_name="wscript.exe"
    OR process_name="cscript.exe"
)
```

Command line:

```spl
index=windows
| search process_name="powershell.exe"
| table _time host user parent_process_name process_name process_path command_line
```

---

# 10. PowerShell investigation

### Find PowerShell

```spl
index=windows
(
    process_name="powershell.exe"
    OR Image="*\\powershell.exe"
)
```

### Suspicious keywords

```spl
index=windows
powershell
(
    "-enc"
    OR "-encodedcommand"
    OR "FromBase64String"
    OR "IEX"
    OR "Invoke-Expression"
    OR "DownloadString"
    OR "DownloadFile"
    OR "WebClient"
    OR "Invoke-WebRequest"
)
```

### Base64-looking commands

```spl
index=windows
powershell
| regex command_line="(?i)(-enc|-encodedcommand)"
| table _time host user command_line
```

### PowerShell by user

```spl
index=windows process_name="powershell.exe"
| stats count by user host
| sort -count
```

---

# 11. Command execution

```spl
index=windows
(
    process_name="cmd.exe"
    OR process_name="powershell.exe"
)
| table _time host user parent_process_name process_name command_line
```

Look for:

```text
whoami
ipconfig
systeminfo
net user
net localgroup
nltest
tasklist
quser
hostname
arp
route
netstat
```

SPL:

```spl
index=windows
(
    "whoami"
    OR "systeminfo"
    OR "net user"
    OR "net localgroup"
    OR "nltest"
    OR "tasklist"
    OR "ipconfig"
    OR "netstat"
)
| table _time host user command_line
```

---

# 12. Credential attacks

## Failed logins

```spl
index=windows
EventCode=4625
| stats count by user src_ip host
| sort -count
```

## Successful logins

```spl
index=windows
EventCode=4624
| stats count by user src_ip host Logon_Type
| sort -count
```

## Failed → successful

Very useful:

```spl
index=windows
(EventCode=4625 OR EventCode=4624)
| stats
    count(eval(EventCode=4625)) as failures
    count(eval(EventCode=4624)) as successes
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by user src_ip
| where failures > 5 AND successes > 0
| sort -failures
```

This is a **triage heuristic**, not proof of compromise.

---

# 13. Password spraying

```spl
index=windows EventCode=4625
| stats
    dc(user) as unique_users
    count as failures
    values(user) as users
    by src_ip
| where unique_users >= 10
| sort -unique_users
```

The key idea:

**one IP → many usernames → authentication failures**

---

# 14. Brute force

```spl
index=windows EventCode=4625
| bin _time span=5m
| stats count as failures by _time src_ip user
| where failures >= 10
```

---

# 15. Kerberoasting-style investigation

Look for Kerberos service ticket requests, depending on your Windows logging/CIM mapping.

Example raw Windows Security:

```spl
index=windows EventCode=4769
| stats count by user Service_Name src_ip
| sort -count
```

Look for:

- unusual service accounts
    
- unusual source hosts
    
- bursts of ticket requests
    
- RC4 usage where relevant to your environment
    
- accounts requesting tickets they don't normally request
    

---

# 16. Pass-the-ticket / unusual Kerberos activity

Useful Windows events include:

```text
4768
4769
4770
4771
```

Search:

```spl
index=windows
(EventCode=4768 OR EventCode=4769 OR EventCode=4770 OR EventCode=4771)
| stats count by EventCode user src_ip host
```

---

# 17. Privilege escalation

Look for:

```text
4672
4728
4729
4732
4733
4756
4757
```

Example:

```spl
index=windows
(EventCode=4672 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time host user src_ip EventCode TargetUserName Group_Name
```

Admin-group changes:

```spl
index=windows
(EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| stats count by user TargetUserName Group_Name host
```

---

# 18. New account creation

```spl
index=windows EventCode=4720
| table _time host user TargetUserName Account_Name
```

Account deletion:

```spl
index=windows EventCode=4726
| table _time host user TargetUserName
```

Account modification:

```spl
index=windows EventCode=4738
| table _time host user TargetUserName
```

---

# 19. Persistence

Search for suspicious:

```text
scheduled tasks
services
registry run keys
startup folders
new accounts
WMI
PowerShell
DLL registration
```

### Scheduled tasks

```spl
index=windows
(
    "schtasks"
    OR "Scheduled Task"
    OR EventCode=4698
)
| table _time host user command_line Task_Name
```

### Windows services

```spl
index=windows
(
    "service"
    OR "sc.exe"
    OR EventCode=7045
)
| table _time host user service_name command_line
```

---

# 20. Registry persistence

Search:

```spl
index=windows
(
    "Run"
    OR "RunOnce"
    OR "CurrentVersion\\Run"
)
```

Then investigate:

```spl
| table _time host user registry_path registry_value command_line
```

---

# 21. LOLBins

Huge category.

Look for:

```text
powershell.exe
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
certutil.exe
bitsadmin.exe
msiexec.exe
wmic.exe
wscript.exe
cscript.exe
installutil.exe
msbuild.exe
cmstp.exe
reg.exe
net.exe
sc.exe
schtasks.exe
```

Generic:

```spl
index=windows
(
    process_name="powershell.exe"
    OR process_name="rundll32.exe"
    OR process_name="regsvr32.exe"
    OR process_name="mshta.exe"
    OR process_name="certutil.exe"
    OR process_name="bitsadmin.exe"
    OR process_name="msiexec.exe"
    OR process_name="wmic.exe"
)
| stats count by process_name host user
```

---

# 22. Defense evasion

Look for:

```text
wevtutil
auditpol
net stop
sc stop
Set-MpPreference
Add-MpPreference
Disable-WindowsOptionalFeature
Clear-EventLog
vssadmin
wbadmin
bcdedit
```

Example:

```spl
index=windows
(
    "wevtutil"
    OR "auditpol"
    OR "Set-MpPreference"
    OR "Add-MpPreference"
    OR "vssadmin"
    OR "wbadmin"
    OR "bcdedit"
)
| table _time host user command_line
```

---

# 23. Windows event log clearing

```spl
index=windows EventCode=1102
| table _time host user src_ip
```

System event log service activity may also appear in System logs depending on collection.

---

# 24. Antivirus tampering

```spl
index=windows
(
    "Set-MpPreference"
    OR "DisableRealtimeMonitoring"
    OR "DisableBehaviorMonitoring"
    OR "ExclusionPath"
    OR "ExclusionExtension"
)
| table _time host user command_line
```

---

# 25. Discovery

Attackers love discovery because it is noisy.

Search for:

```text
whoami
hostname
systeminfo
ipconfig
net user
net group
net localgroup
nltest
dsquery
tasklist
qwinsta
quser
arp
route
netstat
```

```spl
index=windows
(
    "whoami"
    OR "hostname"
    OR "systeminfo"
    OR "ipconfig"
    OR "net user"
    OR "net group"
    OR "net localgroup"
    OR "nltest"
    OR "tasklist"
    OR "qwinsta"
    OR "quser"
    OR "arp"
    OR "netstat"
)
| stats count by host user process_name command_line
| sort -count
```

---

# 26. Network discovery

```spl
index=network
| stats count by src_ip dest_ip dest_port
| sort -count
```

Host scanning:

```spl
index=firewall
| stats dc(dest_ip) as destinations values(dest_ip) as targets by src_ip
| where destinations > 50
| sort -destinations
```

Port scanning:

```spl
index=firewall
| stats dc(dest_port) as ports dc(dest_ip) as hosts by src_ip
| where ports > 20
| sort -ports
```

---

# 27. Lateral movement

Look for:

```text
RDP
SMB
WinRM
WMI
PsExec
SSH
remote services
```

### RDP

```spl
index=windows
(EventCode=4624 OR EventCode=1149)
| search Logon_Type=10
| stats count by user src_ip host
```

### SMB

```spl
index=windows
(EventCode=4624 OR EventCode=5140 OR EventCode=5145)
| stats count by user src_ip host Share_Name
```

### Remote service

```spl
index=windows
(
    "psexec"
    OR "RemCom"
    OR "sc.exe"
)
| table _time host user src_ip command_line
```

---

# 28. WMI

```spl
index=windows
(
    "wmic.exe"
    OR "WmiPrvSE.exe"
    OR "wmiprvse"
)
| table _time host user parent_process_name process_name command_line
```

Pay particular attention to:

```text
wmic process call create
```

and remote WMI execution.

---

# 29. Data staging

Search for archive utilities:

```spl
index=windows
(
    "7z.exe"
    OR "7za.exe"
    OR "rar.exe"
    OR "winrar"
    OR "tar.exe"
    OR "Compress-Archive"
)
| table _time host user command_line
```

Large file activity:

```spl
index=*
| stats sum(bytes) as total_bytes by src_ip dest_ip
| sort -total_bytes
```

---

# 30. Exfiltration

Look for:

```text
unusual outbound traffic
large uploads
cloud storage
FTP
SFTP
HTTP POST
DNS tunneling
new external destinations
```

### Top outbound destinations

```spl
index=firewall
| stats sum(bytes_out) as bytes_out count by src_ip dest_ip
| sort -bytes_out
```

### Large outbound transfers

```spl
index=firewall
| stats sum(bytes_out) as bytes_out by src_ip dest_ip
| where bytes_out > 100000000
| sort -bytes_out
```

---

# 31. DNS investigation

```spl
index=dns
| stats count by src_ip query
| sort -count
```

Rare domains:

```spl
index=dns
| rare query
```

Long DNS queries:

```spl
index=dns
| eval query_length=len(query)
| where query_length > 50
| table _time src_ip query query_length
| sort -query_length
```

Potentially suspicious:

```spl
index=dns
| stats dc(src_ip) as clients count by query
| sort -clients
```

---

# 32. DNS tunneling heuristic

```spl
index=dns
| eval qlen=len(query)
| eval labels=mvcount(split(query,"."))
| stats
    count
    avg(qlen) as avg_length
    max(qlen) as max_length
    dc(src_ip) as clients
    by query
| where avg_length > 50 AND count > 20
| sort -count
```

Again: **heuristic, not verdict**.

---

# 33. Web attacks

## SQL injection

Look for:

```text
UNION SELECT
OR 1=1
SLEEP(
WAITFOR DELAY
xp_cmdshell
information_schema
```

```spl
index=web
(
    "UNION SELECT"
    OR "OR 1=1"
    OR "SLEEP("
    OR "WAITFOR DELAY"
    OR "xp_cmdshell"
    OR "information_schema"
)
| table _time src_ip uri status user_agent
```

---

# 34. XSS

```spl
index=web
(
    "<script"
    OR "javascript:"
    OR "onerror="
    OR "onload="
    OR "document.cookie"
)
| table _time src_ip uri http_user_agent
```

---

# 35. Path traversal

```spl
index=web
(
    "../"
    OR "..\\"
    OR "%2e%2e"
    OR "%252e%252e"
)
| table _time src_ip uri status
```

---

# 36. Command injection

```spl
index=web
(
    ";whoami"
    OR "|whoami"
    OR "&&whoami"
    OR ";id"
    OR "|id"
    OR "`id`"
)
| table _time src_ip uri status
```

---

# 37. Webshell hunting

Look for suspicious requests:

```spl
index=web
(
    ".php"
    OR ".jsp"
    OR ".aspx"
)
| stats count by uri src_ip
| sort -count
```

Then focus on unusual POST requests:

```spl
index=web method=POST
| stats count by uri src_ip
| sort -count
```

Potential shell keywords:

```spl
index=web
(
    "cmd="
    OR "exec="
    OR "shell="
    OR "command="
    OR "powershell"
    OR "whoami"
)
```

---

# 38. Brute-force web login

```spl
index=web action=login
| stats
    count as attempts
    dc(user) as users
    by src_ip
| where attempts > 50
| sort -attempts
```

---

# 39. Cloud investigation

For AWS/Azure/M365/etc., don't blindly use Windows-style fields.

First:

```spl
index=*
| stats count by sourcetype
| sort -count
```

Then identify your cloud sourcetypes.

### AWS suspicious API activity

Conceptually investigate:

```text
CreateUser
CreateAccessKey
AttachUserPolicy
AttachRolePolicy
PutUserPolicy
AssumeRole
ConsoleLogin
GetCallerIdentity
CreateRole
```

Example:

```spl
index=aws
| stats count by userIdentity.arn eventName sourceIPAddress
| sort -count
```

---

# 40. Impossible travel

If your authentication data has geographic fields:

```spl
index=auth
| sort user _time
| streamstats current=f window=1 values(src_ip) as previous_ip by user
```

Better approach is to enrich IPs with geo and calculate distance/time.

Look for:

```text
India → US → 20 minutes
```

That's not necessarily malicious, but it deserves investigation.

---

# 41. First-seen behavior

One of the best SOC tricks.

```spl
index=*
| stats earliest(_time) as first_seen latest(_time) as last_seen count by user src_ip
```

For a suspicious process:

```spl
index=windows process_name="powershell.exe"
| stats earliest(_time) as first_seen latest(_time) as last_seen count by host user
```

---

# 42. Rare process

```spl
index=windows
| stats count by process_name
| sort count
```

Look at the bottom.

```spl
index=windows
| rare process_name
```

Rare ≠ malicious.

But:

**rare + unsigned + unusual path + unusual user + network connection**

is much more interesting.

---

# 43. Parent-child process analysis

This is extremely valuable for endpoint investigations.

```spl
index=windows
| stats count by parent_process_name process_name
| sort -count
```

Look for suspicious chains such as:

```text
winword.exe → powershell.exe
excel.exe → cmd.exe
outlook.exe → powershell.exe
browser.exe → cmd.exe
w3wp.exe → powershell.exe
sqlservr.exe → cmd.exe
```

Query:

```spl
index=windows
(
    parent_process_name="winword.exe"
    OR parent_process_name="excel.exe"
    OR parent_process_name="outlook.exe"
)
(
    process_name="powershell.exe"
    OR process_name="cmd.exe"
    OR process_name="wscript.exe"
)
| table _time host user parent_process_name process_name command_line
```

---

# 44. Process → network correlation

This is gold when endpoint telemetry supports it.

Conceptually:

```text
process
 ↓
PID
 ↓
destination IP
 ↓
destination port
 ↓
DNS
 ↓
user
 ↓
host
```

For example:

```spl
index=*
| search process_name="powershell.exe"
| stats
    values(dest_ip) as destinations
    values(dest_port) as ports
    values(user) as users
    values(host) as hosts
    count
    by process_name
```

---

# 45. Suspicious external connections

```spl
index=firewall
| stats count by src_ip dest_ip dest_port
| lookup known_good_destinations dest_ip OUTPUT category
| where isnull(category)
| sort -count
```

---

# 46. C2 hunting

Look for:

- periodic connections
    
- rare destinations
    
- long-lived sessions
    
- uncommon ports
    
- unusual user agents
    
- newly registered domains
    
- high DNS entropy
    
- beacon-like intervals
    

Basic periodicity:

```spl
index=firewall
| bin _time span=5m
| stats count by src_ip dest_ip _time
| sort src_ip dest_ip _time
```

Then inspect repeated intervals manually.

---

# 47. Beaconing

A simple heuristic:

```spl
index=firewall
| bin _time span=1m
| stats count by src_ip dest_ip _time
| stats
    count as intervals
    dc(_time) as unique_times
    by src_ip dest_ip
| where intervals > 20
```

Better detection requires calculating inter-arrival times.

---

# 48. IOC hunting

If you receive:

```text
IP
domain
hash
URL
email
username
hostname
```

search it everywhere.

### IP

```spl
index=* "1.2.3.4"
```

### Domain

```spl
index=* "evil-example.com"
```

### Hash

```spl
index=* "SHA256_HASH"
```

### URL

```spl
index=* "http://example.com/path"
```

### Email

```spl
index=* "attacker@example.com"
```

---

# 49. IOC → timeline

```spl
index=* "1.2.3.4"
| sort 0 _time
| table _time host user src_ip dest_ip process_name command_line uri _raw
```

This is your **poor man's incident timeline**.

---

# 50. Build a timeline

```spl
index=* host="WIN01" earliest=-24h
| sort 0 _time
| table _time sourcetype user src_ip dest_ip process_name command_line action
```

Export it if needed.

---

# 51. Timeline around an alert

If alert occurred at `10:30`:

```spl
index=* host="WIN01"
earliest="08/16/2026:10:00:00"
latest="08/16/2026:11:00:00"
| sort 0 _time
```

I normally investigate:

```text
-30 minutes
-2 hours
-24 hours
-7 days
```

depending on the attack.

---

# 52. Find what changed

Compare:

```spl
index=windows earliest=-24h
| stats count by process_name
```

versus historical baseline:

```spl
index=windows earliest=-30d@d latest=-7d@d
| stats count by process_name
```

The concept:

**current behavior − historical behavior = anomaly candidates**

---

# 53. Baseline a user

```spl
index=auth user="alice"
| stats count by src_ip
| sort -count
```

Then ask:

> Is today's IP normal for Alice?

---

# 54. Baseline a host

```spl
index=windows host="WIN01"
| stats count by user process_name
| sort -count
```

Then:

> Is this user/process normal on this machine?

---

# 55. Baseline destination

```spl
index=firewall src_ip="10.10.10.5"
| stats count by dest_ip dest_port
| sort -count
```

Then:

> Is this endpoint normally talking to this destination?

---

# 56. Regex extraction

Splunk's `rex` supports PCRE-based extraction. ([Splunk Docs](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex?utm_source=chatgpt.com "rex - Splunk Documentation"))

```spl
... | rex field=_raw "user=(?<username>\S+)"
```

IP extraction:

```spl
... | rex field=_raw "(?<ip>\d{1,3}(?:\.\d{1,3}){3})"
```

Domain:

```spl
... | rex field=_raw "(?<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
```

---

# 57. `eval` cheat sheet

```spl
| eval suspicious=if(count>10,1,0)
```

```spl
| eval duration=last_time-first_time
```

```spl
| eval lower_user=lower(user)
```

```spl
| eval command_length=len(command_line)
```

```spl
| eval is_external=if(cidr(dest_ip,"10.0.0.0/8"),0,1)
```

---

# 58. `stats` cheat sheet

```spl
| stats count
```

```spl
| stats count by user
```

```spl
| stats dc(src_ip) by user
```

```spl
| stats values(src_ip) by user
```

```spl
| stats earliest(_time) latest(_time) by user
```

```spl
| stats
    count
    dc(src_ip) as unique_ips
    values(src_ip) as ips
    by user
```

---

# 59. `eventstats`

Useful when you don't want to collapse events:

```spl
index=windows
| eventstats count by user
| where count > 100
```

---

# 60. `streamstats`

Previous event:

```spl
index=auth
| sort 0 user _time
| streamstats current=f window=1 latest(src_ip) as previous_ip by user
```

This is useful for:

- login sequences
    
- IP changes
    
- process sequences
    
- temporal correlations
    

---

# 61. `transaction`

`transaction` groups events according to constraints and can calculate duration/event count, but it can be expensive on large datasets. ([Splunk Docs](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/Transaction?utm_source=chatgpt.com "transaction - Splunk Documentation"))

Example:

```spl
index=web user="alice"
| transaction session_id maxspan=30m
| table _time duration eventcount
```

Don't reach for `transaction` automatically.

Prefer:

```spl
stats
streamstats
eventstats
```

when possible.

---

# 62. `tstats`

When you have CIM/data models, this can dramatically speed up investigations.

Example:

```spl
| tstats count
  from datamodel=Authentication
  by Authentication.user Authentication.src
```

Network:

```spl
| tstats count
  from datamodel=Network_Traffic
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
```

Endpoint:

```spl
| tstats count
  from datamodel=Endpoint.Processes
  by Processes.process Processes.parent_process Processes.dest
```

Exact fields depend on your CIM/data model implementation.

---

# 63. Risk-based investigation

If you're using Splunk Enterprise Security, don't investigate only the individual alert.

Look at:

```text
Risk object
    ↓
Risk events
    ↓
MITRE tactics
    ↓
MITRE techniques
    ↓
Other detections
    ↓
Timeline
```

Splunk ES can aggregate risk associated with entities and use MITRE ATT&CK enrichment in finding-based detections. ([Splunk Docs](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/detections/create-finding-based-detections-in-splunk-enterprise-security?utm_source=chatgpt.com "Create finding-based detections in Splunk Enterprise Security | Platform (last updated 2026-07-23T21:40:08.308Z)"))

Conceptually:

```spl
| tstats
    sum(All_Risk.calculated_risk_score) as risk_score
    count as risk_events
    values(All_Risk.annotations.mitre_attack.mitre_technique_id) as techniques
    values(All_Risk.annotations.mitre_attack.mitre_tactic) as tactics
    from datamodel=Risk.All_Risk
    by All_Risk.risk_object
```

---

# 64. MITRE ATT&CK investigation map

Use this mental model:

|ATT&CK area|Splunk investigation|
|---|---|
|Recon|DNS/firewall/web|
|Initial Access|VPN/email/web/auth|
|Execution|process/PowerShell|
|Persistence|services/tasks/registry|
|Priv Esc|groups/tokens/UAC|
|Defense Evasion|logs/AV/process|
|Credential Access|auth/Kerberos/LSASS|
|Discovery|commands/network|
|Lateral Movement|RDP/SMB/WMI/WinRM|
|Collection|files/database|
|C2|DNS/firewall/proxy|
|Exfiltration|proxy/firewall/DLP|
|Impact|ransomware/delete/encryption|

Splunk Security Essentials can map ATT&CK techniques to available detections, which is worth using instead of manually maintaining every detection yourself. ([Splunk Docs](https://docs.splunk.com/Documentation/SSE/latest/User/SecurityContent?utm_source=chatgpt.com "Review your content with the Security Content page - Splunk Documentation"))

---

# 65. The 10-query emergency kit

If you have **30 seconds** to triage an alert, run these.

### 1. What happened?

```spl
index=* "IOC"
| sort 0 _time
| table _time host user src_ip dest_ip process_name command_line action
```

### 2. Who?

```spl
index=* "IOC"
| stats count by user
| sort -count
```

### 3. Which host?

```spl
index=* "IOC"
| stats count by host
| sort -count
```

### 4. Which IP?

```spl
index=* "IOC"
| stats count by src_ip dest_ip
| sort -count
```

### 5. Which process?

```spl
index=* "IOC"
| stats count by process_name
| sort -count
```

### 6. When?

```spl
index=* "IOC"
| stats earliest(_time) as first latest(_time) as last
```

### 7. What else did the user do?

```spl
index=* user="USER"
| sort 0 _time
```

### 8. What else happened on the host?

```spl
index=* host="HOST"
| sort 0 _time
```

### 9. Did they authenticate elsewhere?

```spl
index=windows user="USER" EventCode=4624
| stats count by host src_ip Logon_Type
```

### 10. What happened immediately before/after?

```spl
index=* host="HOST"
earliest=-30m latest=+30m
| sort 0 _time
```

---

# 66. The investigation pivot chain

This is the part I'd actually memorize:

```text
ALERT
  ↓
IOC
  ↓
TIME
  ↓
USER
  ↓
SOURCE IP
  ↓
HOST
  ↓
PROCESS
  ↓
COMMAND LINE
  ↓
PARENT PROCESS
  ↓
NETWORK CONNECTION
  ↓
DNS
  ↓
OTHER HOSTS
  ↓
OTHER USERS
  ↓
PERSISTENCE
  ↓
LATERAL MOVEMENT
  ↓
C2 / EXFIL
```

If you consistently follow this chain, your investigations become dramatically faster.

---

# 67. Don't make this mistake

Avoid:

```spl
index=* | search *
```

and then trying to reason about millions of events.

Start narrow:

```text
IOC
↓
time
↓
host
↓
user
↓
process
```

Then widen.

Also avoid using `transaction` everywhere. `stats`, `eventstats`, `streamstats`, and data-model `tstats` are generally better tools for scalable investigations. ([Splunk Docs](https://docs.splunk.com/Documentation/SCS/current/SearchReference/CompatibilityreferenceforSPLcommandfunctions?utm_source=chatgpt.com "Compatibility library for SPL commands as functions - Splunk Documentation"))

---

# 68. The real cheat-sheet structure I'd recommend

For actual SOC work, keep **six tabs**:

```text
01 - SPL BASICS
02 - WINDOWS
03 - NETWORK
04 - CLOUD
05 - WEB
06 - MITRE ATT&CK
```

And inside Windows:

```text
Authentication
Credential Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Discovery
Lateral Movement
Collection
C2
Exfiltration
Ransomware
```

