
## 1. What is DCSync?

**DCSync** is an Active Directory credential-access technique that abuses the **AD replication protocol (DRSUAPI)** to request credential data from a Domain Controller.

The attacker doesn't need to:

- Copy `NTDS.dit`
    
- Create a Volume Shadow Copy
    
- Access the DC's disk directly
    

Instead:

```text
Attacker
   ↓
Has replication privileges
   ↓
Abuses DRSUAPI
   ↓
Requests directory replication data
   ↓
Domain Controller responds
   ↓
Password hashes / credential data obtained
```

### 🧠 Memory Trick

> **DCSync = "Pretend to be a Domain Controller and abuse replication."**

---

# 2. When Does DCSync Become Possible?

The attacker needs appropriate **AD replication rights**.

Common principals with these rights include:

- Domain Admins
    
- Enterprise Admins
    
- Domain Controller machine accounts
    

Attackers can also potentially obtain replication rights through **ACL/permission abuse**.

Example concept:

```text
WriteDACL on domain object
        ↓
Modify permissions
        ↓
Grant replication rights
        ↓
DCSync
```

---

# 3. Important Replication Rights

Three important extended rights:

|GUID|Permission|
|---|---|
|`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`|**DS-Replication-Get-Changes-All**|
|`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`|**DS-Replication-Get-Changes**|
|`89e95b76-444d-4c62-991a-0facbeda640c`|**DS-Replication-Get-Changes-In-Filtered-Set**|

### 🚨 Most important

```text
1131f6ad
```

=

**DS-Replication-Get-Changes-All**

This is the key GUID for detecting replication access capable of retrieving sensitive credential data.

---

# 4. Main Detection Event

## Event 4662

**4662 = An operation was performed on an object**

DCSync detection relies on Directory Service Access auditing.

### Important fields

|Field|Meaning|
|---|---|
|`user`|Account performing replication|
|`Access_Mask`|Access type|
|`Properties`|Replication/control-access information|
|`Logon_ID`|Session identifier used for correlation|

### Detection pattern

```text
EventCode=4662
+
Access_Mask=0x100
+
1131f6ad
+
Suspicious replication account/source
```

---

# 5. What Does `0x100` Mean?

```text
Access_Mask = 0x100
```

= **Control Access**

It indicates that an extended control-access right was exercised.

When combined with the replication GUID, it becomes highly relevant to DCSync detection.

---

# 6. Main DCSync Detection Query

Lab index:

```text
task5
```

Query:

```spl
index=task5 EventCode=4662 "1131f6ad" user!="*$"
| table _time, user, Access_Mask, Properties
| sort _time
```

### What it does

```text
4662
 ↓
Search replication GUID
 ↓
Exclude machine accounts
 ↓
Identify human account
 ↓
Investigate
```

---

# 7. Why Search `"1131f6ad"` as a Keyword?

In this lab, Splunk doesn't necessarily extract the individual replication GUID into a dedicated field.

The GUID exists inside the **raw event data / Properties**.

Therefore:

```spl
"1131f6ad"
```

is used as a keyword search.

Don't assume:

```spl
Properties="1131f6ad"
```

will work in every dataset.

### SOC lesson

> **Know how your SIEM parses the raw event before writing the detection.**

---

# 8. Why Exclude `$` Accounts?

Machine accounts normally end with:

```text
$
```

Example:

```text
THM-DC$
SERVER01$
```

Domain Controllers legitimately perform replication.

So in the lab:

```spl
user!="*$"
```

helps isolate human accounts.

---

# 9. ⚠️ Production Caveat

Don't blindly use:

```spl
user!="*$"
```

as your entire production detection.

Why?

An attacker could compromise a **machine account** and use its replication privileges.

Therefore:

### Lab

```text
Exclude $
```

### Mature SOC

```text
Monitor ALL replication-capable accounts
+
Baseline legitimate replication
+
Detect unusual sources
```

---

# 10. Normal vs Suspicious Replication

|Feature|Normal|Suspicious|
|---|---|---|
|Account|DC machine account|Human account|
|Account ending|`$`|Usually not `$`|
|Source|Domain Controller|Workstation/non-DC|
|Frequency|Regular replication|One-time/burst|
|Behavior|Expected replication|Unusual credential replication|
|Scope|Normal directory changes|Broad credential extraction|

### Key idea

> **DCSync can look like legitimate AD replication. Source and account context are critical.**

---

# 11. Production Detection Logic

Don't think:

```text
4662 + GUID = automatically malicious
```

Think:

```text
4662
+
Replication GUID
+
Who performed it?
+
Where did it originate?
+
Is the source a DC?
+
Does the account normally replicate?
+
Was the activity expected?
```

---

# 12. Important Telemetry Gap

DCSync detection using Event 4662 requires **two things configured beforehand**:

### 1. Audit Directory Service Access

Must be enabled through Group Policy.

### 2. SACL

A SACL must be configured on the relevant domain partition to audit replication operations.

Without both:

```text
DCSync
 ↓
No appropriate 4662
 ↓
Detection gap
```

### 🚨 SOC lesson

> **No log doesn't mean no attack. It may mean no telemetry.**

---

# 13. Getting the Source IP

Event 4662 doesn't directly provide the source IP.

Use **Logon_ID correlation**.

```text
4662
 ↓
Logon_ID
 ↓
4624
 ↓
Source_Network_Address
```

---

# 14. Step 1 — Find Logon_ID

Replace `{COMPROMISED_USER}`:

```spl
index=task5 EventCode=4662 Access_Mask=0x100 user={COMPROMISED_USER} "1131f6ad"
| table _time, host, user, Logon_ID
```

Extract:

```text
Logon_ID
```

---

# 15. Step 2 — Find Source IP

Replace `{LOGON_ID}`:

```spl
index=task5 EventCode=4624 Logon_ID={LOGON_ID}
| table _time, host, user, Source_Network_Address, Logon_Type
```

Now you can identify:

- Source IP
    
- User
    
- Host
    
- Logon type
    

---

# 16. DCSync Investigation Flow

```text
4662
 ↓
Find replication GUID
 ↓
Identify user
 ↓
Check Access_Mask
 ↓
Check whether account normally replicates
 ↓
Identify source host
 ↓
Correlate Logon_ID
 ↓
Find 4624
 ↓
Extract Source_Network_Address
 ↓
Investigate source machine
```

---

# 17. Example Suspicious Pattern

```text
4662
User: DOMAIN\jsmith
Access: 0x100
GUID: 1131f6ad
       ↓
Logon_ID correlation
       ↓
4624
Source: 10.10.20.55
       ↓
10.10.20.55 = Employee workstation
       ↓
🚨 Suspicious DCSync
```

Why?

A normal employee workstation should generally **not be performing domain replication**.

---

# 18. High-Confidence DCSync Pattern

```text
Human account
      +
Replication rights
      +
1131f6ad
      +
0x100
      +
Non-DC source
      +
Unexpected activity
      ↓
🚨 HIGH-CONFIDENCE DCSync
```

---

# 19. DCSync vs LSASS Dumping

| Feature | LSASS Dumping | DCSync |
|---|---|---|
| **Location** | Endpoint | Domain Controller interaction |
| **Target** | `lsass.exe` | AD replication |
| **Main event** | **Sysmon 10** | **Event 4662** |
| **Method** | Process memory access | DRSUAPI |
| **Needs DC disk access?** | ❌ No | ❌ No |
| **Needs replication rights?** | ❌ No | ✅ Yes |
| **Source IP** | Usually endpoint telemetry | Correlate **4662 → 4624** |
| **Main goal** | Steal live credentials | Retrieve AD credential data |
### Memory

> **LSASS = steal credentials from memory.**  
> **DCSync = request credentials through replication.**

---

# 20. DCSync vs NTDS.dit

| Feature | DCSync | NTDS.dit Extraction |
|---|---|---|
| **Method** | Replication abuse | Database extraction |
| **Protocol** | DRSUAPI | Filesystem / VSS / IFM |
| **Direct disk access** | ❌ No | ✅ Yes |
| **Main detection** | **Event 4662** | **Sysmon Event 1 / 11** |
| **Shadow copy** | ❌ No | ✅ Possible |
| **NTDS.dit copied?** | ❌ No | ✅ Yes |
| **Replication rights** | ✅ Required | ❌ Not required |
| **DC access** | Remote protocol | Privileged local/DC access |

### Memory trick

```text
DCSync
→ "Ask the DC"

NTDS.dit
→ "Copy the database"
```

---

# 21. SOC L1 Triage Checklist

```markdown
## DCSync Triage

- [ ] Confirm Event 4662
- [ ] Check Access_Mask = 0x100
- [ ] Check for replication GUID 1131f6ad
- [ ] Identify the `user`
- [ ] Determine whether account is a machine account
- [ ] Determine whether account normally has replication rights
- [ ] Identify source host
- [ ] Extract Logon_ID
- [ ] Correlate with Event 4624
- [ ] Identify Source_Network_Address
- [ ] Determine whether source is a DC
- [ ] Check account activity timeline
- [ ] Check for other credential-access activity
- [ ] Check for privilege escalation
- [ ] Escalate if unauthorized replication is confirmed
```

---

# ⚡ 22. DCSync 30-Second Cheat Sheet

```text
DCSYNC
→ Abuse AD replication
→ Protocol: DRSUAPI

REQUIRES
→ Replication rights

MAIN EVENT
→ 4662

ACCESS MASK
→ 0x100

KEY GUID
→ 1131f6ad

1131f6ad =
DS-Replication-Get-Changes-All

LAB QUERY
→ index=task5 EventCode=4662 "1131f6ad" user!="*$"

SOURCE IP
→ 4662 Logon_ID
→ correlate with 4624
→ Source_Network_Address

NORMAL
→ DC machine accounts
→ DC-to-DC replication

SUSPICIOUS
→ Human account
→ Non-DC source
→ Unexpected replication

TELEMETRY REQUIREMENTS
→ Audit Directory Service Access
→ SACL on domain partition

CRITICAL
→ Don't rely only on user!="*$"
→ Baseline legitimate replication
```

---

# 🧠 23. Interview Answer

> **DCSync is an Active Directory credential-access technique that abuses the DRSUAPI replication protocol to request directory credential data without directly accessing the Domain Controller's disk or copying NTDS.dit. An attacker needs appropriate replication rights, which are commonly held by highly privileged accounts. For detection, I would monitor Event 4662 for Control Access (`0x100`) combined with replication rights such as DS-Replication-Get-Changes-All (`1131f6ad`). I would then determine whether the requesting account and source host are legitimate replication actors. Because Event 4662 doesn't directly contain the source IP, I can correlate its Logon_ID with Event 4624 to obtain the source network address.**

### 🔥 One-line memory

> **`4662 + 0x100 + 1131f6ad + unexpected replication source = investigate DCSync.`**