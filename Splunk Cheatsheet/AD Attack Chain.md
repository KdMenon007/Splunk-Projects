
## 0. 🧠 The Investigation Model

```text
1. DISCOVERY
      ↓
2. ACCOUNT / AD ENUMERATION
      ↓
3. KERBEROS / CREDENTIAL ACCESS
      ↓
4. INITIAL REMOTE AUTHENTICATION
      ↓
5. LATERAL MOVEMENT
      ↓
6. REMOTE EXECUTION
      ↓
7. PERSISTENCE / DEPLOYMENT
      ↓
8. DEFENSE EVASION
      ↓
9. RANSOMWARE EXECUTION
```

Your core correlation fields:

```text
_time
host
User / Account_Name
Source_Network_Address / Client_Address
Logon_ID / LogonId
Image
ParentImage
CommandLine
Service_Name
Service_File_Name
```

### Golden rule

```text
TIME
+
USER
+
SOURCE
+
DESTINATION
+
LOGON ID
+
PROCESS
+
PARENT PROCESS
+
COMMAND LINE
=
ATTACK STORY
```

---

# 1. 🔎 AD DISCOVERY

## 1.1 Sysmon Event 1 — Discovery Commands

```spl
index=win EventCode=1
| search CommandLine IN (
    "*nltest*",
    "*net user*",
    "*net group*",
    "*net view*",
    "*net localgroup*"
)
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

### Look for

```text
nltest
net user
net group
net view
net localgroup
```

---

# 2. 🔍 `nltest` Discovery

```spl
index=win EventCode=1
| search CommandLine="*nltest*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

### Common discovery

```text
nltest /dclist
nltest /domain_trusts
```

### SOC question

```text
Who ran it?
From which host?
When?
What exactly was queried?
Was it followed by lateral movement?
```

---

# 3. 👤 Domain User Discovery

```spl
index=win EventCode=1
| search CommandLine="*net user*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

---

# 4. 👥 Domain Group Discovery

```spl
index=win EventCode=1
| search CommandLine="*net group*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

---

# 5. 🛡️ Local Administrator Discovery

```spl
index=win EventCode=1
| search CommandLine="*net localgroup*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

Especially investigate:

```text
net localgroup administrators
```

---

# 6. 🌐 Network / Host Discovery

```spl
index=win EventCode=1
| search CommandLine="*net view*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

---

# 7. 🟦 PowerShell AD Discovery — Event 4104

```spl
index=win EventCode=4104
| search Message IN (
    "*Get-ADUser*",
    "*Get-ADGroupMember*",
    "*Get-ADComputer*"
)
| table _time, host, User, Message
| sort _time
```

### Important commands

```text
Get-ADUser
Get-ADGroupMember
Get-ADComputer
```

---

# 8. 👤 PowerShell — AD Users

```spl
index=win EventCode=4104
| search Message="*Get-ADUser*"
| table _time, host, User, Message
| sort _time
```

---

# 9. 👥 PowerShell — Group Enumeration

```spl
index=win EventCode=4104
| search Message="*Get-ADGroupMember*"
| table _time, host, User, Message
| sort _time
```

Pay particular attention to:

```text
Domain Admins
Enterprise Admins
Administrators
Backup Operators
Account Operators
```

---

# 10. 🖥️ PowerShell — Computer Enumeration

```spl
index=win EventCode=4104
| search Message="*Get-ADComputer*"
| table _time, host, User, Message
| sort _time
```

---

# 11. 📊 AD Discovery — User Baseline

```spl
index=win EventCode=1
| search CommandLine IN (
    "*nltest*",
    "*net user*",
    "*net group*",
    "*net view*",
    "*net localgroup*"
)
| stats count values(CommandLine) as Commands by User
| sort -count
```

### Question

```text
Does this user normally perform AD discovery?
```

---

# 12. 🖥️ AD Discovery — Host Baseline

```spl
index=win EventCode=1
| search CommandLine IN (
    "*nltest*",
    "*net user*",
    "*net group*",
    "*net view*",
    "*net localgroup*"
)
| stats count values(CommandLine) as Commands by host
| sort -count
```

---

# 13. 🔗 User + Host + Commands

```spl
index=win EventCode=1
| search CommandLine IN (
    "*nltest*",
    "*net user*",
    "*net group*",
    "*net view*",
    "*net localgroup*"
)
| stats count values(CommandLine) as Commands by User, host
| sort -count
```

This is one of the most useful L1 queries.

---

# 14. 🧭 AD DISCOVERY → LATERAL MOVEMENT

Once you identify:

```text
User
Host
Timestamp
```

pivot into:

```spl
index=win EventCode=4624 User="<USER>"
| table _time, host, User, Logon_Type, Source_Network_Address, Logon_ID
| sort _time
```

Then:

```spl
index=win EventCode=4648 User="<USER>"
| table _time, host, User, Target_Server_Name, Logon_ID
| sort _time
```

And:

```spl
index=win EventCode=4768 Account_Name="<USER>"
| table _time, Account_Name, Client_Address
| sort _time
```

```spl
index=win EventCode=4769 Account_Name="<USER>"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

---

# 15. 🔐 KERBEROS — Event 4768

## What is 4768?

```text
4768
↓
TGT requested
↓
Kerberos authentication activity
```

### Hunt

```spl
index=win EventCode=4768
| table _time, Account_Name, Client_Address
| sort _time
```

### Investigate

```text
Account_Name
Client_Address
Time
```

---

# 16. 🎫 KERBEROS — Event 4769

```text
4769
↓
TGS requested
↓
Service accessed
```

### General hunt

```spl
index=win EventCode=4769
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

---

# 17. 🔥 KERBEROASTING — RC4

RC4:

```text
0x17
```

Detection:

```spl
index=win EventCode=4769
Ticket_Encryption_Type=0x17
Service_Name!="*$"
Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

### Why?

Potential:

```text
Kerberoasting
```

But:

```text
RC4 ≠ automatically Kerberoasting
```

Context matters.

---

# 18. 🎯 Kerberoasting — Multiple SPNs

```spl
index=win EventCode=4769
Service_Name!="*$"
Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5
| sort _time
```

### Interpretation

```text
One user
+
One source
+
Many different services
+
Short time window
=
High-interest Kerberos activity
```

`>5` is a **lab starting point**, not a universal production threshold.

---

# 19. 🎫 Kerberos — Count by Account

```spl
index=win EventCode=4769
| stats count by Account_Name
| sort -count
```

---

# 20. 🌐 Kerberos — Count by Source

```spl
index=win EventCode=4769
| stats count by Client_Address
| sort -count
```

---

# 21. 🎯 Kerberos — Count by Service

```spl
index=win EventCode=4769
| stats count by Service_Name
| sort -count
```

---

# 22. 🔎 Investigate One Account

```spl
index=win EventCode=4769 Account_Name="<USERNAME>"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

---

# 23. 🔎 Investigate One Source

```spl
index=win EventCode=4769 Client_Address="<SOURCE_IP>"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type
| sort _time
```

---

# 24. 🔑 EVENT 4648 — EXPLICIT CREDENTIALS

```text
4648
↓
Explicit credentials were used
```

### Hunt

```spl
index=win EventCode=4648
| table _time, host, User, Target_Server_Name, Logon_ID
| sort _time
```

### Investigate

```text
Original user
Target
Time
Logon ID
```

Potentially important during:

```text
Credential misuse
Lateral movement
RunAs activity
Administrative access
```

---

# 25. 🚪 EVENT 4624 — SUCCESSFUL LOGON

```spl
index=win EventCode=4624
| table _time, host, User, Logon_Type, Source_Network_Address, Logon_ID
| sort _time
```

This is your **main authentication pivot**.

---

# 26. 🧠 LOGON TYPES

|Type|Meaning|SOC Interest|
|--:|---|---|
|2|Interactive|Local logon|
|3|Network|SMB/network authentication|
|4|Batch|Scheduled/batch|
|5|Service|Service account|
|7|Unlock|Workstation unlock|
|8|NetworkCleartext|Investigate|
|9|NewCredentials|RunAs-style activity|
|10|RemoteInteractive|RDP|
|11|CachedInteractive|Cached credentials|

### Memorize first

```text
2  = Interactive
3  = Network
5  = Service
10 = RDP
```

---

# 27. 🖥️ RDP — Event 4624 Type 10

```spl
index=win EventCode=4624 Logon_Type=10
| table _time, host, User, Source_Network_Address, Logon_ID
| sort _time
```

### Investigate

```text
Source
Destination
User
Time
LogonId
```

---

# 28. 🧭 RDP SOURCE → DESTINATION

Look for:

```text
Workstation → Server
```

Usually expected in many environments.

Investigate:

```text
Workstation → Workstation
Server → Server
Server → Domain Controller
```

Especially:

```text
Unexpected source
+
Privileged account
+
Off-hours
+
New destination
```

---

# 29. 🔗 RDP + NLA

Search:

```spl
index=win EventCode=4624
| search Logon_Type=3 OR Logon_Type=10
| table _time, host, User, Logon_Type, Source_Network_Address, Logon_ID
| sort _time
```

Potential pattern:

```text
Type 3
↓
Type 10
↓
Same source
↓
Same account
↓
Seconds apart
```

This can be associated with NLA/RDP authentication behavior.

---

# 30. 🖥️ RDP CLIENT — `mstsc.exe`

If you identify the source machine:

```spl
index=win EventCode=1 host="<SOURCE_HOST>"
| search Image="*mstsc.exe*"
| table _time, host, User, Image, CommandLine, LogonId
| sort _time
```

### Meaning

```text
mstsc.exe
↓
Windows Remote Desktop client
↓
Outbound RDP activity
```

---

# 31. 🔗 RDP CHAIN USING LOGON ID

Take:

```text
Logon_ID
```

Then:

```spl
index=win EventCode=4624 host="<HOST>" Logon_ID="<LOGON_ID>"
| table _time, User, Logon_Type, Source_Network_Address, Logon_ID
| sort _time
```

Then pivot:

```text
Source IP
↓
Source host
↓
mstsc.exe
↓
New destination
```

---

# 32. 🏢 SMB — EVENT 5140

```text
5140
↓
Network share accessed
```

### Admin share hunt

```spl
index=win EventCode=5140
| search Share_Name="*ADMIN$*" OR Share_Name="*C$*"
| table _time, host, Source_Address, User, Share_Name
| sort _time
```

---

# 33. 📁 SMB — EVENT 5145

```text
5145
↓
Detailed network-share access
```

```spl
index=win EventCode=5145
| table _time, host, User, Source_Address, Share_Name, Relative_Target_Name
| sort _time
```

---

# 34. 🔥 ADMIN$ / C$ INVESTIGATION

```spl
index=win EventCode=5140
| search Share_Name="*ADMIN$*" OR Share_Name="*C$*"
| table _time, host, Source_Address, User, Share_Name
| sort _time
```

Then investigate:

```text
4624
5145
Sysmon 1
7045
```

---

# 35. 👤 SMB USER BASELINE

```spl
index=win EventCode=5140 User="<USER>"
| table _time, Source_Address, Share_Name, host
| sort _time
```

Compare:

```text
Normal source
vs
New source
```

```text
Normal share
vs
ADMIN$ / C$
```

---

# 36. 🖥️ SOURCE IP → MACHINE ACCOUNT

```spl
index=win EventCode=4624
Source_Network_Address="<SOURCE_IP>"
| search User="*$"
| stats count by User, Source_Network_Address
| sort -count
```

Example:

```text
THM-SRV-01$
```

Machine hostname:

```text
THM-SRV-01
```

---

# 37. 💻 SOURCE HOST → ADMIN$ COMMAND

```spl
index=win EventCode=1 host="<SOURCE_HOST>"
| search CommandLine="*ADMIN$*"
| table _time, User, Image, CommandLine, ParentImage
| sort _time
```

Important:

```text
Process User
≠
necessarily credential used for remote authentication
```

That's why you correlate with:

```text
4624
4648
5140
5145
```

---

# 38. ⚙️ PSEXEC — EVENT 7045

```text
7045
↓
New Windows service installed
```

```spl
index=win EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| sort _time
```

---

# 39. 🟥 PSEXESVC

Classic PsExec:

```text
PSEXESVC
```

Potential service:

```text
PSEXESVC
```

Possible binary:

```text
C:\Windows\PSEXESVC.exe
```

But **do not rely on the name**.

Attackers can rename services.

---

# 40. ⚙️ SERVICE-BASED REMOTE EXECUTION

```spl
index=win EventCode=7045
| search Service_Start_Type="*demand*"
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Account
| sort _time
```

Investigate:

```text
New service
+
Unexpected binary
+
Unexpected account
+
Remote authentication
```

---

# 41. 💻 PSEXEC CHILD PROCESS

```spl
index=win EventCode=1 host="<DESTINATION_HOST>"
| search ParentImage="*PSEXESVC*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

Possible children:

```text
cmd.exe
powershell.exe
whoami.exe
net.exe
rundll32.exe
```

---

# 42. 🔌 PSEXEC — SYSMON 17

```text
Sysmon 17
↓
Named pipe created
```

```spl
index=win EventCode=17
| search Image="*PSEXESVC*"
| table _time, host, Image, PipeName
| sort _time
```

Possible:

```text
PSEXESVC-*-stdin
PSEXESVC-*-stdout
PSEXESVC-*-stderr
```

Again:

```text
Behavior > filename
```

---

# 43. 📂 PSEXEC — EVENT 5145

```spl
index=win EventCode=5145
| search Relative_Target_Name="*PSEXE*"
| table _time, host, User, Source_Address, Share_Name, Relative_Target_Name
| sort _time
```

---

# 44. 🔗 PSEXEC CORRELATION

The strongest investigation pattern:

```text
4624
   ↓
5140
   ↓
5145
   ↓
7045
   ↓
Sysmon 1
   ↓
Sysmon 17
```

Think:

```text
Remote authentication
↓
SMB access
↓
File/service transfer
↓
Service installation
↓
Remote process
↓
Named pipe
```

Not every PsExec execution will produce every event in every telemetry configuration, so treat this as a **correlation model**, not a mandatory sequence.

---

# 45. 🖥️ WMIC REMOTE EXECUTION

```spl
index=win EventCode=1
| search Image="*wmic.exe*" OR ParentImage="*WmiPrvSE.exe*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

### Investigate

```text
wmic.exe
↓
WMI
↓
WmiPrvSE.exe
↓
Child process
```

Look for:

```text
Unexpected remote WMI activity
+
cmd.exe
+
powershell.exe
+
script execution
```

---

# 46. ⏰ SCHEDULED TASK — PROCESS CREATION

```spl
index=win EventCode=1
| search Image="*schtasks.exe*" OR CommandLine="*schtasks*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

---

# 47. ⏰ SCHEDULED TASK — EVENT 4698

```spl
index=win EventCode=4698
| table _time, host, User, Task_Name
| sort _time
```

Investigate:

```text
Task name
Creator
Execution time
Command/script
Target host
```

---

# 48. 🚨 SCHEDULED TASK DEPLOYMENT

High-interest pattern:

```text
schtasks
+
Remote target
+
New task
+
Multiple hosts
+
Similar timing
```

---

# 49. 🖥️ RMM-BASED DEPLOYMENT

If the organization uses an RMM:

```spl
index=win EventCode=1
| search ParentImage="*ScreenConnect*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

Adapt to your actual RMM:

```text
ScreenConnect
ConnectWise
AnyDesk
TeamViewer
other approved RMM
```

The detection logic is:

```text
RMM agent
↓
unexpected child process
↓
script / executable
↓
many endpoints
↓
similar timing
```

---

# 50. 🏢 GPO / SYSVOL

GPO ransomware deployment generally requires **correlation** rather than one magic Event ID.

Search process activity involving SYSVOL:

```spl
index=win EventCode=1
| search CommandLine="*SYSVOL*" OR Image="*SYSVOL*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

Correlate:

```text
GPO modification
+
SYSVOL modification
+
Startup/Logon execution
+
Mass endpoint execution
```

---

# 51. 🦠 RANSOMWARE PREPARATION

## Shadow Copies / Recovery

```spl
index=win EventCode=1
| search CommandLine IN (
    "*vssadmin*",
    "*wbadmin*",
    "*shadow*",
    "*backup*",
    "*recovery*"
)
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

### Important

These commands can be legitimate.

```text
Detection ≠ confirmed ransomware
```

---

# 52. 💣 VSSADMIN

```spl
index=win EventCode=1
| search CommandLine="*vssadmin*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

High-interest when associated with:

```text
delete shadows
```

---

# 53. 💾 WBADMIN

```spl
index=win EventCode=1
| search CommandLine="*wbadmin*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

---

# 54. 🧹 SECURITY LOG CLEARING — EVENT 1102

```spl
index=win EventCode=1102
| table _time, host, User
| sort _time
```

Meaning:

```text
Security event log cleared
```

High priority when:

```text
Unexpected
+
Immediately after suspicious activity
```

---

# 55. 💥 DESTRUCTIVE COMMANDS

```spl
index=win EventCode=1
| search CommandLine IN (
    "*format*",
    "*cipher*",
    "*diskpart*",
    "*wbadmin*",
    "*vssadmin*"
)
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

Again:

```text
format ≠ ransomware
cipher ≠ ransomware
diskpart ≠ ransomware
```

Context is king.

---

# 56. 🔥 RANSOMWARE DEPLOYMENT CORRELATION

Look for:

```text
Discovery
   ↓
Credential access
   ↓
4624 / 4648
   ↓
SMB / RDP / WMI / PsExec
   ↓
Scheduled Task / GPO / RMM
   ↓
Shadow copy deletion
   ↓
Log clearing
   ↓
Mass process execution
   ↓
Encryption / destruction
```

---

# 57. 🧪 MASS EXECUTION HUNT

One useful approach is to find the same command across multiple hosts:

```spl
index=win EventCode=1
| stats dc(host) as hosts values(host) as HostList count by Image, CommandLine
| where hosts > 5
| sort -hosts
```

This can reveal:

```text
Same executable
+
Same command
+
Many hosts
```

Potential deployment activity.

Tune the threshold to your environment.

---

# 58. 👤 DISCOVERY USER BASELINE

```spl
index=win EventCode=1
| search CommandLine IN (
    "*nltest*",
    "*net user*",
    "*net group*",
    "*net view*",
    "*net localgroup*"
)
| stats count values(host) as Hosts values(CommandLine) as Commands by User
| sort -count
```

---

# 59. 🖥️ LATERAL MOVEMENT USER BASELINE

```spl
index=win EventCode=4624
| search Logon_Type=3 OR Logon_Type=10
| stats dc(host) as Destinations values(host) as Hosts by User, Source_Network_Address
| sort -Destinations
```

This helps answer:

```text
Which account
from which source
authenticated to
how many systems?
```

---

# 60. 🚨 MULTI-HOST AUTHENTICATION

```spl
index=win EventCode=4624
| search Logon_Type=3 OR Logon_Type=10
| stats dc(host) as destination_hosts values(host) as Hosts by User, Source_Network_Address
| where destination_hosts > 5
| sort -destination_hosts
```

Potentially useful for detecting:

```text
Credential spraying
Lateral movement
Admin activity
Automated deployment
```

Baseline first.

---

# 61. 🔗 SOURCE IP INVESTIGATION

When you have:

```text
Source_Network_Address = 10.x.x.x
```

search:

```spl
index=win EventCode=4624 Source_Network_Address="10.x.x.x"
| stats count values(User) as Users values(host) as Destinations by Source_Network_Address
```

Now you know:

```text
Source
↓
Users
↓
Destination systems
```

---

# 62. 🧭 USER INVESTIGATION

```spl
index=win User="<USER>"
| stats count by EventCode
| sort -count
```

This gives you a quick view of which Windows events are associated with the account.

Then drill into:

```text
4624
4648
4768
4769
5140
5145
7045
4698
1102
Sysmon 1
4104
```

---

# 63. 🖥️ HOST INVESTIGATION

```spl
index=win host="<HOST>"
| stats count by EventCode
| sort -count
```

Useful for determining:

```text
What happened on this machine?
```

---

# 64. ⏱️ TIMELINE INVESTIGATION

Once you have a suspicious user:

```spl
index=win User="<USER>"
| table _time, EventCode, host, User, Source_Network_Address, Logon_Type, Image, ParentImage, CommandLine
| sort _time
```

This is your basic **SOC timeline**.

---

# 65. 🧠 THE FULL AD ATTACK CHAIN

```text
┌──────────────────────────────┐
│       AD DISCOVERY           │
│                              │
│ Sysmon 1                     │
│ 4104                         │
│ nltest                       │
│ net user                     │
│ net group                    │
│ net view                     │
│ Get-ADUser                   │
│ Get-ADComputer               │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│      KERBEROS ACTIVITY       │
│                              │
│ 4768                         │
│ 4769                         │
│ RC4 0x17                     │
│ Multiple SPNs                │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│     CREDENTIAL MISUSE        │
│                              │
│ 4648                         │
│ Explicit credentials         │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│      REMOTE AUTHENTICATION   │
│                              │
│ 4624                         │
│ Type 3                       │
│ Type 10                      │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│      LATERAL MOVEMENT        │
│                              │
│ RDP                          │
│ SMB                          │
│ ADMIN$                       │
│ C$                           │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│      REMOTE EXECUTION        │
│                              │
│ PsExec                       │
│ 7045                         │
│ Sysmon 17                    │
│ WMI                          │
│ Scheduled Tasks              │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│        DEPLOYMENT            │
│                              │
│ GPO                          │
│ RMM                          │
│ WMIC                         │
│ schtasks                     │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│     RANSOMWARE PREP          │
│                              │
│ VSS                           │
│ WBADMIN                      │
│ Shadow Copies                │
│ Recovery                     │
│ Backup destruction           │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│      DEFENSE EVASION         │
│                              │
│ 1102                         │
│ Log clearing                 │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│       MASS EXECUTION         │
│                              │
│ Same process                 │
│ Same command                 │
│ Multiple hosts               │
└──────────────┬───────────────┘
               ↓
          🚨 RANSOMWARE
```

# 66. 📌 MASTER EVENT TABLE

|Event|Meaning|Primary SOC Use|
|---|---|---|
|**Sysmon 1**|Process creation|Command/process investigation|
|**Sysmon 17**|Named pipe created|PsExec/IPC investigation|
|**4104**|PowerShell Script Block|PowerShell activity|
|**4624**|Successful logon|Authentication/lateral movement|
|**4648**|Explicit credentials|Credential misuse|
|**4698**|Scheduled task created|Persistence/deployment|
|**4768**|Kerberos TGT request|Kerberos authentication|
|**4769**|Kerberos TGS request|Kerberoasting/service access|
|**5140**|Network share accessed|SMB|
|**5145**|Detailed share access|SMB/file activity|
|**7045**|Service installed|PsExec/service-based execution|
|**1102**|Security log cleared|Defense evasion|
|**4688**|Windows process creation|Process investigation if Sysmon unavailable|

---

# 67. ⚡ SOC L1 — 30-SECOND MEMORY

```text
AD DISCOVERY
→ Sysmon 1
→ 4104

KERBEROS
→ 4768
→ 4769

KERBEROASTING
→ 4769
→ RC4 0x17
→ Multiple unique SPNs

CREDENTIAL MISUSE
→ 4648

REMOTE LOGIN
→ 4624

RDP
→ 4624 Type 10
→ mstsc.exe

SMB
→ 5140
→ 5145

PSEXEC
→ 7045
→ Sysmon 1
→ Sysmon 17
→ 5145

WMI
→ wmiprvse.exe
→ Child process

SCHEDULED TASK
→ 4698
→ schtasks

RMM
→ RMM agent
→ Suspicious child

GPO
→ GPO changes
→ SYSVOL
→ Mass execution

RANSOMWARE
→ VSSADMIN
→ WBADMIN
→ Shadow Copies
→ 1102
→ Mass execution
```

# 68. 🔥 SOC L1 → L2 INVESTIGATION FORMULA

When an alert lands, don't immediately start firing 25 SPL queries like a caffeinated raccoon.

Use this:

```text
STEP 1
What happened?

        ↓

STEP 2
Which USER?

        ↓

STEP 3
Which HOST?

        ↓

STEP 4
What SOURCE IP?

        ↓

STEP 5
What DESTINATION?

        ↓

STEP 6
What PROCESS?

        ↓

STEP 7
What COMMAND LINE?

        ↓

STEP 8
What PARENT PROCESS?

        ↓

STEP 9
What LOGON ID?

        ↓

STEP 10
What happened immediately BEFORE?

        ↓

STEP 11
What happened immediately AFTER?

        ↓

STEP 12
Can I build a complete attack timeline?
```

## 🧠 The five pivots you should memorize first

```text
USER
HOST
SOURCE IP
TIME
LOGON ID
```

Then add:

```text
PROCESS
PARENT PROCESS
COMMAND LINE
```

That turns Splunk from **"searching logs"** into actual **SOC investigation**.