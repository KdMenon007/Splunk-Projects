
## 1️⃣ Kerberoasting

**Target:** SPN/service accounts  
**Requirement:** Usually a valid domain account  
**Goal:** Obtain TGS → offline crack service-account password

```text
User → TGS Request → DC → TGS → Offline Crack
```

### Detection

**Event:** `4769` — Kerberos Service Ticket Requested

|Field|Meaning|
|---|---|
|`Account_Name`|Requester|
|`Service_Name`|Target SPN/service|
|`Client_Address`|Source IP|
|`Ticket_Encryption_Type`|Encryption|

### Encryption

```text
0x12 → AES-256
0x11 → AES-128
0x17 → RC4-HMAC 🚨
```

### Strong signal

```text
4769
+ 0x17
+ multiple SPNs
+ short time window
= Kerberoasting suspicion
```

### Reduce noise

```spl
Service_Name!="*$"
Service_Name!="krbtgt"
```

### Aggregate

```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
```

### Modern detection

Don't rely only on RC4:

```text
One account
→ many unique SPNs
→ short time
→ suspicious
```

Lab threshold:

```text
>5 unique SPNs / 5 minutes
```

---

# 2️⃣ AS-REP Roasting

**Target:** Accounts with preauthentication disabled  
**SPN required:** ❌  
**Valid domain credentials:** Not necessarily required  
**Goal:** Obtain AS-REP → offline crack password

### Detection

**Event:** `4768` — TGT Request

```text
Pre_Authentication_Type=0 🚨
```

### Normal

```text
Pre_Authentication_Type=2
```

### Query

```spl
index=task3 EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
```

### Investigate follow-up

```text
4768
 ↓
No 4769
No 4624
 ↓
More suspicious
```

### Memory

```text
Kerberoasting → SPN → TGS → 4769

AS-REP Roasting → No Preauth → TGT → 4768
```

---

# 3️⃣ LSASS Dumping

**Target:** `lsass.exe`  
**Goal:** Steal live credentials/tickets from memory

### Detection

**Sysmon Event 10 — ProcessAccess**

|Field|Meaning|
|---|---|
|`SourceImage`|Process accessing LSASS|
|`SourceUser`|Account running it|
|`TargetImage`|Target process|
|`GrantedAccess`|Requested permissions|
|`CallTrace`|Access method|

### Important access

```text
0x0010 → PROCESS_VM_READ
0x1010 → Query + VM Read
0x1FFFFF → PROCESS_ALL_ACCESS
```

### CallTrace

```text
dbgcore.dll / dbghelp.dll
→ MiniDump-style

UNKNOWN offsets
→ Possible injected/in-memory code
```

### Detection query

```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe"
| stats count by SourceImage, GrantedAccess
```

### ⚠️ Always check full path

```text
C:\Windows\System32\svchost.exe → potentially legitimate

C:\Users\Public\svchost.exe → 🚨 suspicious
```

---

# 4️⃣ DCSync

**Target:** AD credential data  
**Method:** Abuse AD replication / DRSUAPI  
**Requirement:** Replication privileges

### Detection

**Event:** `4662`

### Key values

```text
Access_Mask = 0x100
```

Important GUID:

```text
1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
```

= **DS-Replication-Get-Changes-All**

### Query

```spl
index=task5 EventCode=4662 "1131f6ad" user!="*$"
| table _time, user, Access_Mask, Properties
| sort _time
```

### Source IP correlation

```text
4662
 ↓
Logon_ID
 ↓
4624
 ↓
Source_Network_Address
```

### Important

Normal:

```text
DC$ → DC
```

Suspicious:

```text
Human account
+
Workstation/non-DC
+
Replication rights
```

⚠️ Don't blindly exclude `$` in mature environments; compromised machine accounts can potentially perform replication.

---

# 5️⃣ NTDS.dit Extraction

**Target:** `NTDS.dit`  
**Location:**

```text
C:\Windows\NTDS\ntds.dit
```

Contains domain credential information.

### Common methods

```text
vssadmin
→ Shadow Copy
→ Copy NTDS.dit + SYSTEM

ntdsutil
→ IFM
→ Create database copy
```

### Detection

**Sysmon Event 1:** Process Creation

```spl
index=task6 EventCode=1 Image="*\ntdsutil.exe"
| table _time, host, User, ParentImage, Image, CommandLine
```

Look for:

```text
ifm
create
```

### Confirm NTDS.dit

**Sysmon Event 11**

```spl
index=task6 EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
| table _time, Image, TargetFilename
```

### Detect VSS

```spl
index=task6 EventCode=1 Image="*\vssadmin.exe" CommandLine="*create shadow*"
| table _time, host, User, ParentImage, Image, CommandLine
```

Then investigate:

```text
ShadowCopy
+
NTDS.dit
+
SYSTEM
=
🚨 High confidence credential extraction
```

---

# 🧠 MASTER TABLE

|Attack|Target|Event|Key Signal|
|---|---|---|---|
|🔥 Kerberoasting|SPN/service account|**4769**|`0x17` + many SPNs|
|🔥 AS-REP Roasting|No-preauth account|**4768**|`PreAuth=0`|
|🔥 LSASS Dump|`lsass.exe`|**Sysmon 10**|Suspicious ProcessAccess|
|🔥 DCSync|AD replication|**4662**|`0x100` + `1131f6ad`|
|🔥 NTDS.dit|AD database|**Sysmon 1/11**|`ntdsutil` / `vssadmin`|

---

# ⚡ VALUES TO MEMORIZE

```text
4768  → TGT request
4769  → TGS request
4624  → Successful logon

4662  → Directory Service Access

Sysmon 1  → Process Creation
Sysmon 10 → Process Access
Sysmon 11 → File Creation
```

```text
0x11 → AES-128
0x12 → AES-256
0x17 → RC4-HMAC

0x0010   → PROCESS_VM_READ
0x1010   → Query + VM Read
0x1FFFFF → ALL_ACCESS

0x100 → Control Access
```

```text
1131f6ad
↓
DS-Replication-Get-Changes-All
↓
DCSync detection
```

---

# 🎯 SOC TRIAGE FORMULA

For **any AD credential-access alert**, ask:

```text
WHO?
→ Account / SourceUser

WHAT?
→ Service / Process / Target

WHERE?
→ Source IP / Host

WHEN?
→ Timeline

HOW?
→ Encryption / Access Mask / CommandLine

HOW MANY?
→ Volume / Unique targets

NORMAL?
→ Baseline comparison

PRIVILEGED?
→ What access does the account have?

IMPACT?
→ What credentials could be obtained?
```

### 🏆 Ultimate memory line

> **4769 = Kerberoast, 4768 = AS-REP, Sysmon 10 = LSASS, 4662 = DCSync, Sysmon 1/11 = NTDS.dit.**