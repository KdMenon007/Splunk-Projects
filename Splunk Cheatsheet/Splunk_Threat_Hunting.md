# Splunk SOC Threat Hunting & Investigation Cheat Sheet

**Included query patterns: 192+**

**Purpose:** fast defensive investigation and detection engineering
reference for SOC analysts.

**Scope:** Windows/AD, endpoint, network, DNS, web, cloud, Linux, IOC
hunting, incident timelines, MITRE-oriented pivots, and detection QA.

## How to use this

1.  Start narrow: alert/IOC → time → user → host → process → network.
2.  Widen only after you establish the first confirmed fact.
3.  Treat keyword matches and thresholds as **heuristics**, not proof of
    compromise.
4.  Prefer CIM/data-model searches and `tstats` when your environment
    supports them.
5.  Validate field names and sourcetypes against your own Splunk
    deployment.

## Core investigation pivot

`ALERT → IOC → TIME → USER → SOURCE IP → HOST → PROCESS → PARENT → COMMAND LINE → NETWORK → DNS → OTHER HOSTS → PERSISTENCE → LATERAL MOVEMENT → C2/EXFIL`

------------------------------------------------------------------------

## 01 --- SPL Quick Reference

Use these as building blocks. Replace index, field names, and
sourcetypes with the normalized fields in your environment.

### Basic search

``` spl
index=main earliest=-24h
| stats count by sourcetype
| sort -count
```

### Search an IOC

``` spl
index=* earliest=-24h "IOC"
| sort 0 _time
| table _time host user src_ip dest_ip process_name command_line uri action
```

### Top users

``` spl
index=* earliest=-24h
| stats count by user
| sort -count
```

### Top hosts

``` spl
index=* earliest=-24h
| stats count by host
| sort -count
```

### Top source IPs

``` spl
index=* earliest=-24h
| stats count by src_ip
| sort -count
```

### Top destination IPs

``` spl
index=* earliest=-24h
| stats count by dest_ip
| sort -count
```

### First/last seen

``` spl
index=* "IOC"
| stats earliest(_time) as first_seen latest(_time) as last_seen count
```

### Field discovery

``` spl
index=* earliest=-1h
| fieldsummary
```

### Sourcetype inventory

``` spl
index=* earliest=-24h
| stats count by sourcetype
| sort -count
```

### Host/source inventory

``` spl
index=* earliest=-24h
| stats count by host source sourcetype
| sort -count
```

### Extract with rex

``` spl
index=* "user="
| rex field=_raw "user=(?<username>\S+)"
| table _time username _raw
```

### Time bucketing

``` spl
index=* earliest=-24h
| bin _time span=15m
| stats count by _time
```

### Conditional eval

``` spl
index=*
| eval suspicious=if(count>10,1,0)
```

### Distinct count

``` spl
index=*
| stats dc(user) as unique_users dc(src_ip) as unique_ips
```

### Values without collapsing events

``` spl
index=*
| eventstats dc(src_ip) as unique_ips by user
| where unique_ips > 5
```

### Previous event

``` spl
index=auth
| sort 0 user _time
| streamstats current=f window=1 latest(src_ip) as previous_ip by user
```

### Rare values

``` spl
index=*
| rare process_name
```

### Large outbound traffic

``` spl
index=firewall
| stats sum(bytes_out) as bytes_out by src_ip dest_ip
| where bytes_out > 100000000
| sort -bytes_out
```

### tstats authentication

``` spl
| tstats count
  from datamodel=Authentication
  by Authentication.user Authentication.src
```

### tstats network

``` spl
| tstats count
  from datamodel=Network_Traffic
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
```

------------------------------------------------------------------------

## 02 --- Windows Authentication & AD

Assumes Windows Security logs are collected. Event IDs are common
starting points; validate them against your Windows/TA/CIM
implementation.

### Failed logons

``` spl
index=windows EventCode=4625
| stats count by user src_ip host
| sort -count
```

### Successful logons

``` spl
index=windows EventCode=4624
| stats count by user src_ip host Logon_Type
| sort -count
```

### Failed then successful

``` spl
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures
        count(eval(EventCode=4624)) as successes
        earliest(_time) as first_seen
        latest(_time) as last_seen
        by user src_ip
| where failures > 5 AND successes > 0
| sort -failures
```

### Password spraying

``` spl
index=windows EventCode=4625
| stats count as failures dc(user) as unique_users values(user) as users by src_ip
| where unique_users >= 10
| sort -unique_users
```

### Brute force burst

``` spl
index=windows EventCode=4625
| bin _time span=5m
| stats count as failures by _time src_ip user
| where failures >= 10
```

### Account lockouts

``` spl
index=windows
(EventCode=4740 OR "account was locked out")
| stats count by user host src_ip
| sort -count
```

### Special privileges

``` spl
index=windows EventCode=4672
| table _time host user src_ip PrivilegeList
```

### New account

``` spl
index=windows EventCode=4720
| table _time host user TargetUserName Account_Name
```

### Account deleted

``` spl
index=windows EventCode=4726
| table _time host user TargetUserName
```

### Account changed

``` spl
index=windows EventCode=4738
| table _time host user TargetUserName
```

### Added to domain group

``` spl
index=windows (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time host user TargetUserName Group_Name
```

### Removed from domain group

``` spl
index=windows (EventCode=4729 OR EventCode=4733 OR EventCode=4757)
| table _time host user TargetUserName Group_Name
```

### Kerberos ticket requests

``` spl
index=windows EventCode=4769
| stats count by user Service_Name src_ip
| sort -count
```

### Kerberos pre-auth failures

``` spl
index=windows EventCode=4771
| stats count by user src_ip host
| sort -count
```

### Kerberos TGT requests

``` spl
index=windows EventCode=4768
| stats count by user src_ip host
| sort -count
```

### RDP logons

``` spl
index=windows EventCode=4624 Logon_Type=10
| stats count by user src_ip host
| sort -count
```

### Network logons

``` spl
index=windows EventCode=4624 Logon_Type=3
| stats count by user src_ip host
| sort -count
```

### Explicit credentials

``` spl
index=windows EventCode=4648
| table _time host user TargetUserName TargetServerName ProcessName src_ip
```

### Logon type distribution

``` spl
index=windows EventCode=4624
| stats count by Logon_Type
| sort -count
```

### Authentication timeline

``` spl
index=windows user="USER" (EventCode=4624 OR EventCode=4625)
| sort 0 _time
| table _time EventCode host src_ip Logon_Type
```

------------------------------------------------------------------------

## 03 --- PowerShell, Command & LOLBins

Focus on behavior and parent-child relationships rather than a single
keyword. Many legitimate tools are dual-use.

### PowerShell executions

``` spl
index=windows
(process_name="powershell.exe" OR Image="*\\powershell.exe")
| stats count by host user
| sort -count
```

### Encoded PowerShell

``` spl
index=windows powershell
| regex command_line="(?i)(-enc|-encodedcommand)"
| table _time host user parent_process_name command_line
```

### PowerShell download behavior

``` spl
index=windows powershell
("DownloadString" OR "DownloadFile" OR "Invoke-WebRequest" OR "WebClient")
| table _time host user command_line
```

### PowerShell IEX

``` spl
index=windows powershell
("IEX" OR "Invoke-Expression")
| table _time host user parent_process_name command_line
```

### PowerShell base64 API

``` spl
index=windows powershell "FromBase64String"
| table _time host user command_line
```

### CMD executions

``` spl
index=windows process_name="cmd.exe"
| table _time host user parent_process_name command_line
```

### Rundll32

``` spl
index=windows process_name="rundll32.exe"
| table _time host user parent_process_name command_line
```

### Regsvr32

``` spl
index=windows process_name="regsvr32.exe"
| table _time host user parent_process_name command_line
```

### MSHTA

``` spl
index=windows process_name="mshta.exe"
| table _time host user parent_process_name command_line
```

### Certutil

``` spl
index=windows process_name="certutil.exe"
| table _time host user parent_process_name command_line
```

### Bitsadmin

``` spl
index=windows process_name="bitsadmin.exe"
| table _time host user parent_process_name command_line
```

### MSIExec

``` spl
index=windows process_name="msiexec.exe"
| table _time host user parent_process_name command_line
```

### WMIC

``` spl
index=windows process_name="wmic.exe"
| table _time host user parent_process_name command_line
```

### WScript/Cscript

``` spl
index=windows
(process_name="wscript.exe" OR process_name="cscript.exe")
| table _time host user parent_process_name command_line
```

### LOLBins overview

``` spl
index=windows
(process_name="powershell.exe" OR process_name="rundll32.exe" OR process_name="regsvr32.exe"
 OR process_name="mshta.exe" OR process_name="certutil.exe" OR process_name="bitsadmin.exe"
 OR process_name="msiexec.exe" OR process_name="wmic.exe")
| stats count by process_name host user
| sort -count
```

### Suspicious parent-child

``` spl
index=windows
(parent_process_name="winword.exe" OR parent_process_name="excel.exe" OR parent_process_name="outlook.exe")
(process_name="powershell.exe" OR process_name="cmd.exe" OR process_name="wscript.exe")
| table _time host user parent_process_name process_name command_line
```

### Process tree pairs

``` spl
index=windows
| stats count by parent_process_name process_name
| sort -count
```

### Rare process

``` spl
index=windows
| stats count by process_name
| sort count
```

### Long command lines

``` spl
index=windows
| eval command_length=len(command_line)
| where command_length > 500
| table _time host user process_name command_length command_line
| sort -command_length
```

------------------------------------------------------------------------

## 04 --- Persistence & Defense Evasion

Persistence hunting is strongest when correlated with process ancestry,
account context, and first-seen timing.

### Scheduled tasks

``` spl
index=windows (EventCode=4698 OR "schtasks")
| table _time host user Task_Name command_line
```

### Service creation

``` spl
index=windows EventCode=7045
| table _time host user service_name ImagePath ServiceFileName
```

### Service manipulation

``` spl
index=windows ("sc.exe" OR "sc ")
| table _time host user command_line
```

### Run keys

``` spl
index=windows ("CurrentVersion\\Run" OR "RunOnce")
| table _time host user registry_path registry_value command_line
```

### Startup folder

``` spl
index=windows ("Startup" OR "\\Start Menu\\Programs\\Startup")
| table _time host user file_path command_line
```

### WMI persistence

``` spl
index=windows
("WMI" OR "WmiPrvSE.exe" OR "EventFilter" OR "CommandLineEventConsumer")
| table _time host user process_name command_line
```

### Event log clearing

``` spl
index=windows EventCode=1102
| table _time host user src_ip
```

### Audit policy changes

``` spl
index=windows
(EventCode=4719 OR "auditpol")
| table _time host user command_line
```

### Defender preference changes

``` spl
index=windows
("Set-MpPreference" OR "Add-MpPreference" OR "DisableRealtimeMonitoring")
| table _time host user command_line
```

### VSS deletion

``` spl
index=windows
("vssadmin" OR "delete shadows")
| table _time host user command_line
```

### Backup deletion

``` spl
index=windows
("wbadmin" OR "delete catalog")
| table _time host user command_line
```

### Boot configuration changes

``` spl
index=windows
("bcdedit")
| table _time host user command_line
```

### Recursive deletion

``` spl
index=windows
("Remove-Item" OR "rmdir" OR "del /s" OR "rm -rf")
| table _time host user command_line
```

### Hidden files

``` spl
index=windows
("attrib +h" OR "Hidden")
| table _time host user command_line file_path
```

### Suspicious temp execution

``` spl
index=windows
| search process_path="*\\Temp\\*" OR process_path="*\\AppData\\Local\\Temp\\*"
| table _time host user process_name process_path command_line
```

### Unsigned/unusual path candidate

``` spl
index=windows
| search process_path="*\\Users\\Public\\*" OR process_path="*\\ProgramData\\*"
| table _time host user process_name process_path command_line
```

------------------------------------------------------------------------

## 05 --- Discovery & AD Recon

Discovery often becomes obvious when a user or endpoint suddenly
performs many enumeration actions in a short window.

### Whoami

``` spl
index=windows "whoami"
| table _time host user process_name command_line
```

### Systeminfo

``` spl
index=windows "systeminfo"
| table _time host user process_name command_line
```

### Ipconfig

``` spl
index=windows "ipconfig"
| table _time host user process_name command_line
```

### Net user

``` spl
index=windows "net user"
| table _time host user process_name command_line
```

### Net localgroup

``` spl
index=windows "net localgroup"
| table _time host user process_name command_line
```

### Net group

``` spl
index=windows "net group"
| table _time host user process_name command_line
```

### NLTest

``` spl
index=windows "nltest"
| table _time host user process_name command_line
```

### DSQuery

``` spl
index=windows "dsquery"
| table _time host user process_name command_line
```

### Tasklist

``` spl
index=windows "tasklist"
| table _time host user process_name command_line
```

### Quser/Qwinsta

``` spl
index=windows ("quser" OR "qwinsta")
| table _time host user process_name command_line
```

### ARP discovery

``` spl
index=windows "arp "
| table _time host user process_name command_line
```

### Netstat

``` spl
index=windows "netstat"
| table _time host user process_name command_line
```

### Route discovery

``` spl
index=windows "route "
| table _time host user process_name command_line
```

### BloodHound/SharpHound

``` spl
index=windows ("SharpHound" OR "BloodHound")
| table _time host user process_name command_line
```

### Many discovery commands

``` spl
index=windows
("whoami" OR "systeminfo" OR "ipconfig" OR "net user" OR "nltest" OR "tasklist" OR "netstat")
| stats count values(command_line) as commands by host user
| sort -count
```

### Discovery burst

``` spl
index=windows
| bin _time span=10m
| stats count as events values(process_name) as processes values(command_line) as commands by _time host user
| where events > 20
| sort -events
```

### Rare user-host pair

``` spl
index=windows
| stats count by user host
| sort count
```

### New process on host

``` spl
index=windows earliest=-24h
| stats earliest(_time) as first_seen count by host process_name
| sort first_seen
```

------------------------------------------------------------------------

## 06 --- Lateral Movement

Use authentication plus endpoint/network telemetry. A remote login alone
is not proof of lateral movement.

### RDP

``` spl
index=windows EventCode=4624 Logon_Type=10
| stats count by user src_ip host
| sort -count
```

### SMB shares

``` spl
index=windows (EventCode=5140 OR EventCode=5145)
| stats count by user src_ip host Share_Name
| sort -count
```

### WMI

``` spl
index=windows ("wmic.exe" OR "WmiPrvSE.exe")
| table _time host user parent_process_name process_name command_line
```

### PsExec

``` spl
index=windows ("psexec" OR "PSEXESVC")
| table _time host user src_ip process_name command_line
```

### WinRM

``` spl
index=windows ("winrm" OR "wsmprovhost.exe")
| table _time host user src_ip process_name command_line
```

### Remote service creation

``` spl
index=windows EventCode=7045
| stats count by host user service_name ImagePath
| sort -count
```

### Multiple hosts from one source

``` spl
index=windows EventCode=4624 Logon_Type=3
| stats dc(host) as hosts values(host) as destinations by src_ip user
| where hosts > 5
| sort -hosts
```

### One user across many hosts

``` spl
index=windows EventCode=4624
| stats dc(host) as hosts values(host) as destinations by user
| where hosts > 10
| sort -hosts
```

### Admin lateral movement candidates

``` spl
index=windows EventCode=4624
| search Logon_Type=3 OR Logon_Type=10
| stats count by user src_ip host
| sort -count
```

### Remote execution keywords

``` spl
index=windows
("psexec" OR "wmic" OR "winrs" OR "wsmprovhost" OR "schtasks /S")
| table _time host user src_ip command_line
```

------------------------------------------------------------------------

## 07 --- Network, DNS & C2

Network analytics are most useful when you combine volume, rarity,
periodicity, destination reputation, and endpoint context.

### Top connections

``` spl
index=firewall
| stats count by src_ip dest_ip dest_port
| sort -count
```

### Unique destinations per source

``` spl
index=firewall
| stats dc(dest_ip) as destinations values(dest_ip) as targets by src_ip
| sort -destinations
```

### Unique ports per source

``` spl
index=firewall
| stats dc(dest_port) as ports values(dest_port) as ports_seen by src_ip
| sort -ports
```

### Potential port scan

``` spl
index=firewall
| stats dc(dest_port) as ports dc(dest_ip) as hosts by src_ip
| where ports > 20 OR hosts > 50
| sort -ports
```

### Large outbound transfers

``` spl
index=firewall
| stats sum(bytes_out) as bytes_out by src_ip dest_ip
| where bytes_out > 100000000
| sort -bytes_out
```

### DNS top queries

``` spl
index=dns
| stats count by src_ip query
| sort -count
```

### Long DNS queries

``` spl
index=dns
| eval query_length=len(query)
| where query_length > 50
| table _time src_ip query query_length
| sort -query_length
```

### DNS query frequency

``` spl
index=dns
| stats count dc(src_ip) as clients by query
| sort -count
```

### Potential DNS tunneling

``` spl
index=dns
| eval qlen=len(query)
| stats count avg(qlen) as avg_length max(qlen) as max_length dc(src_ip) as clients by query
| where avg_length > 50 AND count > 20
| sort -count
```

### Rare external destinations

``` spl
index=firewall
| stats count by dest_ip
| sort count
```

### Outbound uncommon ports

``` spl
index=firewall
| stats count by dest_port
| sort count
```

### HTTP user agents

``` spl
index=proxy
| stats count by http_user_agent
| sort -count
```

### Suspicious scripting UAs

``` spl
index=proxy
("python-requests" OR "curl/" OR "PowerShell" OR "Go-http-client")
| stats count by src_ip dest_ip http_user_agent
| sort -count
```

### Beacon time buckets

``` spl
index=firewall
| bin _time span=1m
| stats count by src_ip dest_ip _time
| sort 0 src_ip dest_ip _time
```

### Repeated connections

``` spl
index=firewall
| stats count dc(_time) as active_minutes by src_ip dest_ip
| where count > 20 AND active_minutes > 10
| sort -count
```

### External connections from PowerShell

``` spl
index=*
| search process_name="powershell.exe"
| stats count values(dest_ip) as destinations values(dest_port) as ports by host user
| sort -count
```

------------------------------------------------------------------------

## 08 --- Web Attacks

These are detection heuristics. Normalize URL decoding, method, status,
and application context before tuning thresholds.

### SQL injection keywords

``` spl
index=web
("UNION SELECT" OR "OR 1=1" OR "SLEEP(" OR "WAITFOR DELAY" OR "xp_cmdshell" OR "information_schema")
| table _time src_ip uri status http_user_agent
```

### XSS keywords

``` spl
index=web
("<script" OR "javascript:" OR "onerror=" OR "onload=" OR "document.cookie")
| table _time src_ip uri status http_user_agent
```

### Path traversal

``` spl
index=web
("../" OR "..\\" OR "%2e%2e" OR "%252e%252e")
| table _time src_ip uri status
```

### Command injection

``` spl
index=web
(";whoami" OR "|whoami" OR "&&whoami" OR ";id" OR "|id")
| table _time src_ip uri status
```

### Suspicious POST volume

``` spl
index=web method=POST
| stats count by src_ip uri
| where count > 100
| sort -count
```

### Web login brute force

``` spl
index=web action=login
| stats count as attempts dc(user) as users by src_ip
| where attempts > 50
| sort -attempts
```

### HTTP 401 bursts

``` spl
index=web status=401
| bin _time span=5m
| stats count by _time src_ip uri
| where count > 20
| sort -count
```

### HTTP 404 reconnaissance

``` spl
index=web status=404
| stats count dc(uri) as unique_uris by src_ip
| where unique_uris > 50
| sort -unique_uris
```

### Webshell candidates

``` spl
index=web method=POST
(".php" OR ".jsp" OR ".aspx")
("cmd=" OR "exec=" OR "shell=" OR "command=")
| table _time src_ip uri status
```

### File inclusion candidates

``` spl
index=web
("php://" OR "file://" OR "data://" OR "expect://")
| table _time src_ip uri status
```

------------------------------------------------------------------------

## 09 --- Malware, EDR & Endpoint Hunting

Field names vary significantly by EDR. Prefer CIM-normalized Endpoint
data where available.

### Process inventory

``` spl
index=edr
| stats count by dest user process_name
| sort -count
```

### Rare process by host

``` spl
index=edr
| stats count by dest process_name
| sort count
```

### Process network pivots

``` spl
index=edr
| stats count values(dest_ip) as dest_ips values(dest_port) as ports by dest user process_name
| sort -count
```

### Hash pivot

``` spl
index=edr sha256="HASH"
| table _time dest user process_name process_path command_line sha256
```

### File path pivot

``` spl
index=edr file_path="*SUSPICIOUS*"
| table _time dest user process_name file_path command_line
```

### Parent-child anomalies

``` spl
index=edr
| stats count by parent_process_name process_name
| sort -count
```

### Office spawning shell

``` spl
index=edr
(parent_process_name="winword.exe" OR parent_process_name="excel.exe" OR parent_process_name="powerpnt.exe")
(process_name="cmd.exe" OR process_name="powershell.exe" OR process_name="wscript.exe")
| table _time dest user parent_process_name process_name command_line
```

### Browser spawning shell

``` spl
index=edr
(parent_process_name="chrome.exe" OR parent_process_name="msedge.exe" OR parent_process_name="firefox.exe")
(process_name="cmd.exe" OR process_name="powershell.exe")
| table _time dest user parent_process_name process_name command_line
```

### Temporary directory execution

``` spl
index=edr
| search process_path="*\\Temp\\*" OR process_path="*\\AppData\\Local\\Temp\\*"
| table _time dest user process_name process_path command_line
```

### Public directory execution

``` spl
index=edr process_path="*\\Users\\Public\\*"
| table _time dest user process_name process_path command_line
```

------------------------------------------------------------------------

## 10 --- Cloud / AWS / Azure / M365

Cloud schemas differ by provider and add-on. First inventory sourcetypes
and normalize identity, source IP, action, resource, and result fields.

### Cloud event inventory

``` spl
index=cloud
| stats count by sourcetype
| sort -count
```

### AWS actions

``` spl
index=aws
| stats count by userIdentity.arn eventName sourceIPAddress
| sort -count
```

### AWS console logins

``` spl
index=aws eventName=ConsoleLogin
| stats count by userIdentity.arn sourceIPAddress responseElements.ConsoleLogin
| sort -count
```

### AWS access key creation

``` spl
index=aws eventName=CreateAccessKey
| table _time userIdentity.arn sourceIPAddress requestParameters.userName
```

### AWS policy attachment

``` spl
index=aws
(eventName=AttachUserPolicy OR eventName=AttachRolePolicy OR eventName=PutUserPolicy)
| table _time userIdentity.arn sourceIPAddress eventName requestParameters
```

### AWS AssumeRole

``` spl
index=aws eventName=AssumeRole
| stats count by userIdentity.arn sourceIPAddress requestParameters.roleArn
| sort -count
```

### Azure sign-in failures

``` spl
index=azure
("Sign-in activity" OR "SigninLogs")
| search ResultType!=0
| stats count by UserPrincipalName IPAddress AppDisplayName
| sort -count
```

### Azure privileged changes

``` spl
index=azure
("Add member to role" OR "Add eligible member to role" OR "Add owner to application")
| table _time InitiatedBy targetResources ActivityDisplayName
```

### M365 mailbox rules

``` spl
index=m365
("New-InboxRule" OR "Set-InboxRule")
| table _time user Operation Parameters ClientIP
```

### M365 suspicious forwarding

``` spl
index=m365
("ForwardTo" OR "RedirectTo" OR "ForwardAsAttachmentTo")
| table _time user Operation Parameters ClientIP
```

------------------------------------------------------------------------

## 11 --- IOC Hunting & Incident Timeline

Use these pivots after an alert fires. Replace IOC with the actual
observable and then widen the scope.

### IOC everywhere

``` spl
index=* earliest=-7d "IOC"
| sort 0 _time
| table _time index sourcetype host user src_ip dest_ip process_name command_line uri
```

### IOC first/last seen

``` spl
index=* "IOC"
| stats earliest(_time) as first_seen latest(_time) as last_seen count
```

### IOC by host

``` spl
index=* "IOC"
| stats count earliest(_time) as first latest(_time) by host
| sort -count
```

### IOC by user

``` spl
index=* "IOC"
| stats count earliest(_time) as first latest(_time) by user
| sort -count
```

### IOC by source

``` spl
index=* "IOC"
| stats count by src_ip
| sort -count
```

### IOC by destination

``` spl
index=* "IOC"
| stats count by dest_ip
| sort -count
```

### IOC timeline

``` spl
index=* "IOC"
| sort 0 _time
| table _time host user src_ip dest_ip process_name command_line uri action _raw
```

### Host timeline

``` spl
index=* host="HOST" earliest=-24h
| sort 0 _time
| table _time sourcetype user src_ip dest_ip process_name command_line action
```

### User timeline

``` spl
index=* user="USER" earliest=-24h
| sort 0 _time
| table _time sourcetype host src_ip dest_ip process_name command_line action
```

### Alert window

``` spl
index=* host="HOST" earliest=-30m latest=+30m
| sort 0 _time
| table _time sourcetype user src_ip dest_ip process_name command_line action
```

### Entity profile

``` spl
index=*
| stats earliest(_time) as first_seen latest(_time) as last_seen count
  values(src_ip) as src_ips values(dest_ip) as dest_ips
  values(process_name) as processes values(host) as hosts
  by user
```

### User source baseline

``` spl
index=auth user="USER" earliest=-30d
| stats count by src_ip
| sort -count
```

### Host user baseline

``` spl
index=windows host="HOST" earliest=-30d
| stats count by user
| sort -count
```

### Host process baseline

``` spl
index=windows host="HOST" earliest=-30d
| stats count by process_name
| sort -count
```

### New destination candidate

``` spl
index=firewall src_ip="HOST_OR_IP" earliest=-24h
| stats count by dest_ip dest_port
| sort count
```

------------------------------------------------------------------------

## 12 --- Ransomware / Impact

Impact-stage hunting should be correlated with backup, shadow-copy,
process, file, and authentication telemetry.

### Shadow copy deletion

``` spl
index=*
("vssadmin delete shadows" OR "wmic shadowcopy delete")
| table _time host user process_name command_line
```

### Backup deletion

``` spl
index=*
("wbadmin delete catalog" OR "wbadmin delete systemstatebackup")
| table _time host user process_name command_line
```

### Mass file extension changes

``` spl
index=edr
| stats dc(file_extension) as extensions count by dest user
| where extensions > 10
| sort -extensions
```

### High file modification burst

``` spl
index=edr
| bin _time span=5m
| stats count by _time dest user
| where count > 1000
| sort -count
```

### Ransom note candidates

``` spl
index=edr
("README" OR "DECRYPT" OR "RECOVER" OR "RANSOM")
| table _time dest user file_path process_name
```

### Mass process termination

``` spl
index=windows
("taskkill" OR "Stop-Process")
| stats count values(command_line) as commands by host user
| where count > 20
```

### Security tooling tamper

``` spl
index=windows
("Set-MpPreference" OR "sc stop" OR "net stop")
("Defender" OR "WinDefend" OR "Security")
| table _time host user command_line
```

------------------------------------------------------------------------

## 13 --- Linux / Unix

Linux field names depend on auditd, Sysmon for Linux, auth logs, and
your TA. Common auditd fields include uid, auid, exe, comm, syscall, and
success.

### SSH failures

``` spl
index=linux ("Failed password" OR "authentication failure")
| stats count by src_ip user host
| sort -count
```

### SSH successes

``` spl
index=linux ("Accepted password" OR "Accepted publickey")
| stats count by src_ip user host
| sort -count
```

### SSH brute force

``` spl
index=linux "Failed password"
| bin _time span=5m
| stats count by _time src_ip user
| where count >= 10
```

### Sudo usage

``` spl
index=linux ("sudo:" OR "sudo ")
| table _time host user command
```

### Root shell candidates

``` spl
index=linux
("uid=0" OR "euid=0")
| table _time host user exe comm command
```

### New users

``` spl
index=linux
("useradd" OR "adduser")
| table _time host user command
```

### Cron persistence

``` spl
index=linux
("crontab" OR "/etc/cron" OR "/var/spool/cron")
| table _time host user command file_path
```

### SSH key changes

``` spl
index=linux
(".ssh/authorized_keys" OR "authorized_keys")
| table _time host user command file_path
```

### SUID candidates

``` spl
index=linux
("chmod u+s" OR "chmod 4755" OR "setuid")
| table _time host user command
```

### Auditd command execution

``` spl
index=linux sourcetype=*audit*
| search type=EXECVE
| table _time host uid auid exe comm success
```

### Suspicious shell from service

``` spl
index=linux
(parent_process_name="systemd" OR parent_process_name="sshd")
(process_name="bash" OR process_name="sh" OR process_name="zsh")
| table _time host user parent_process_name process_name command_line
```

------------------------------------------------------------------------

## 14 --- Detection Engineering & QA

Use these before promoting a hunting query into an alert. Detection
quality depends on telemetry, normalization, thresholds, and
false-positive analysis.

### Count candidate events

``` spl
<detection search>
| stats count
```

### Estimate unique entities

``` spl
<detection search>
| stats dc(user) as users dc(dest) as hosts dc(src_ip) as src_ips
```

### Inspect false positives

``` spl
<detection search>
| stats count values(user) as users values(dest) as hosts by process_name
| sort -count
```

### Add an allowlist lookup

``` spl
<detection search>
| lookup allowlist field OUTPUT category
| where isnull(category)
```

### Measure first/last seen

``` spl
<detection search>
| stats earliest(_time) as first latest(_time) as last count by user host
```

### Test threshold distribution

``` spl
<baseline search>
| stats count by user
| stats min(count) as min p50(count) as p50 avg(count) as avg max(count) as max
```

### Tune by asset type

``` spl
<detection search>
| stats count by dest asset_category
| sort -count
```

### Tune by privileged users

``` spl
<detection search>
| search user IN ("ADMIN1","ADMIN2")
| stats count by user host
```

### Compare current vs historical

``` spl
index=windows earliest=-24h
| stats count by process_name
| appendcols [
    search index=windows earliest=-30d@d latest=-7d@d
    | stats count by process_name
]
```

### Detection result table

``` spl
<detection search>
| table _time user src_ip dest process_name parent_process_name command_line
| sort 0 -_time
```

------------------------------------------------------------------------

## Windows Event ID quick map

  Event ID    Typical use
  ----------- -------------------------------------
  4624        Successful logon
  4625        Failed logon
  4648        Explicit credentials
  4672        Special privileges assigned
  4698        Scheduled task created
  4719        Audit policy changed
  4720        User created
  4726        User deleted
  4728/4729   Global group membership changes
  4732/4733   Local group membership changes
  4738        User account changed
  4740        Account locked out
  4756/4757   Universal group membership changes
  4768        Kerberos TGT request
  4769        Kerberos service ticket request
  4771        Kerberos pre-authentication failure
  5140        Network share accessed
  5145        Detailed network share access
  7045        Service installed
  1102        Security audit log cleared

**Important:** event availability and field names depend on Windows
audit policy, XML/raw collection, Splunk add-ons, and CIM normalization.

## High-value investigation rules

-   **Rare + privileged + new + external** is usually more interesting
    than any single indicator.
-   A successful login after many failures deserves immediate
    correlation.
-   A process should be evaluated with its **parent, path, user, command
    line, hash, and network activity**.
-   A suspicious IP is only the beginning: pivot to every
    user/host/process it touched.
-   A suspicious process is only the beginning: pivot to every
    destination and child process.
-   A detection that fires constantly is not a detection; it is
    telemetry with an attitude.

## Recommended official references

-   Splunk Security Content: https://github.com/splunk/security_content
-   Splunk Attack Data: https://github.com/splunk/attack_data
-   Splunk Search Reference:
    https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/
