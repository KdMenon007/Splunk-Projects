
## 1. What is NTDS.dit?

`NTDS.dit` is the **Active Directory database** stored on Domain Controllers.

Default location:

```text
C:\Windows\NTDS\ntds.dit
```

It contains credential information for **domain accounts**.

```text
NTDS.dit
   ↓
Active Directory database
   ↓
Domain account credential data
```

### Why can't attackers simply copy it?

Windows locks the database while AD DS is running.

Therefore attackers commonly abuse:

```text
1. Volume Shadow Copy
2. ntdsutil → IFM
```

---

# 2. Method 1 — Volume Shadow Copy

### Tool

```text
vssadmin.exe
```

Concept:

```text
vssadmin
   ↓
Create Shadow Copy
   ↓
Access snapshot
   ↓
Copy NTDS.dit
   ↓
Copy SYSTEM hive
   ↓
Offline credential extraction
```

### Important command-line indicator

```text
create shadow
```

### Detection

```spl
index=task6 EventCode=1 Image="*\vssadmin.exe" CommandLine="*create shadow*"
| table _time, host, User, ParentImage, Image, CommandLine
```

---

# 3. Why SYSTEM Is Also Important

The attacker may copy:

```text
NTDS.dit
+
SYSTEM hive
```

The SYSTEM hive contains information needed to process/decrypt the protected credential material from the AD database.

### Suspicious pattern

```text
Shadow Copy
     +
NTDS.dit
     +
SYSTEM
     ↓
🚨 Credential extraction suspicion
```

---

# 4. Shadow Copy Alone ≠ Malicious

This is important for SOC triage.

`vssadmin create shadow` can be legitimate because:

- Backup software may use it.
    
- System recovery can use it.
    
- Administrative maintenance may create snapshots.
    

Therefore:

```text
vssadmin create shadow
        ↓
Investigate what happens NEXT
```

Look for:

```text
Shadow Copy
   ↓
Access to NTDS.dit
   ↓
Access to SYSTEM
```

That combination is much more suspicious.

---

# 5. Method 2 — ntdsutil IFM

`ntdsutil.exe` is a legitimate Windows/AD administration tool.

Attackers can abuse its:

```text
IFM
```

feature.

**IFM = Install From Media**

Concept:

```text
ntdsutil
   ↓
IFM
   ↓
Create database copy
   ↓
NTDS.dit + SYSTEM
   ↓
Offline extraction
```

### Important command-line indicators

```text
ifm
create
```

---

# 6. ntdsutil Detection

**Sysmon Event 1 = Process Creation**

```spl
index=task6 EventCode=1 Image="*\ntdsutil.exe"
| table _time, host, User, ParentImage, Image, CommandLine
```

### Investigate

```text
Image
CommandLine
ParentImage
User
Host
```

---

# 7. Confirm NTDS.dit Was Created

**Sysmon Event 11 = File Creation**

```spl
index=task6 EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
| table _time, Image, TargetFilename
```

If this returns a result:

```text
ntdsutil.exe
      ↓
NTDS.dit written to disk
      ↓
🚨 Strong evidence of extraction
```

---

# 8. Shadow Copy → Sensitive File Detection

Look for access to the Shadow Copy device path:

```spl
index=task6 EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
| table _time, host, User, ParentImage, Image, CommandLine
```

### Key artifact

```text
HarddiskVolumeShadowCopy
```

Combined with:

```text
ntds
SYSTEM
```

is highly suspicious.

---

# 9. Sysmon Events to Remember

|Sysmon Event|Meaning|NTDS.dit Use|
|---|---|---|
|**Event 1**|Process Creation|Detect `ntdsutil` / `vssadmin`|
|**Event 11**|File Creation|Detect `ntds.dit` being written|

### Memory Trick

> **1 = Process started**  
> **11 = File created**

---

# 10. If Sysmon Isn't Available

Windows Security Event:

```text
4688
```

= **Process Creation**

If command-line logging is enabled, Event 4688 can provide similar visibility to Sysmon Event 1.

```text
Sysmon 1
      OR
Security 4688
      ↓
Process + CommandLine
```

---

# 11. Detection Indicators

### ntdsutil

```text
ntdsutil.exe
+
ifm
+
create
```

### vssadmin

```text
vssadmin.exe
+
create shadow
```

### File creation

```text
ntds.dit
```

### Shadow copy access

```text
HarddiskVolumeShadowCopy
+
ntds
+
SYSTEM
```

---

# 12. DCSync vs NTDS.dit Extraction

| Feature | DCSync | NTDS.dit Extraction |
|---|---|---|
| **Method** | Remote replication via DRSUAPI | Local database extraction |
| **Access needed** | Replication rights | Local/privileged access to DC |
| **Protocol / Mechanism** | DRSUAPI | Filesystem / VSS / IFM |
| **Direct disk access** | ❌ No | ✅ Yes |
| **NTDS.dit copied?** | ❌ No | ✅ Yes |
| **Shadow Copy** | ❌ No | ✅ Possible |
| **Main log source** | Event **4662** | Sysmon **1 / 11** |
| **Network visibility** | Replication traffic | Usually local operation |
| **Noise level** | Lower / blends with replication | Higher / more artifacts |
| **Main technique** | Abuse AD replication | Copy AD database |
| **Credential result** | AD credential data | Offline copy of AD database |

---

# 13. DCSync vs NTDS.dit — Memory Trick


```text
DCSync
→ ASK the Domain Controller

NTDS.dit Extraction
→ COPY the Domain Controller database
```

### DCSync

```text
Attacker
   ↓
DRSUAPI
   ↓
DC
   ↓
Credential data
```

### NTDS.dit

```text
Attacker on DC
   ↓
VSS / IFM
   ↓
NTDS.dit
   ↓
Offline extraction
```

---

# 14. SOC Investigation Flow

```text
                    NTDS.dit Investigation

                              ↓

                    Process Creation?
                              ↓
                 ┌────────────┴────────────┐
                 ↓                         ↓
             ntdsutil.exe              vssadmin.exe
                 ↓                         ↓
             IFM / create             create shadow
                 ↓                         ↓
           Event 11?                  What happened next?
                 ↓                         ↓
            ntds.dit              NTDS.dit + SYSTEM?
                 ↓                         ↓
                 └────────────┬────────────┘
                              ↓
                   Credential extraction?
                              ↓
                         🚨 Escalate
```

---

# 15. SOC L1 Triage Checklist

```markdown
## NTDS.dit Triage

- [ ] Confirm host is a Domain Controller
- [ ] Check Sysmon Event 1
- [ ] Search for `ntdsutil.exe`
- [ ] Search for `vssadmin.exe`
- [ ] Inspect CommandLine
- [ ] Check for `ifm` + `create`
- [ ] Check for `create shadow`
- [ ] Check ParentImage
- [ ] Identify User
- [ ] Check Sysmon Event 11
- [ ] Search for `ntds.dit`
- [ ] Search for `SYSTEM`
- [ ] Search for `HarddiskVolumeShadowCopy`
- [ ] Determine whether activity was legitimate backup/maintenance
- [ ] Correlate events on the timeline
- [ ] Investigate the executing account
- [ ] Escalate if credential extraction is confirmed
```

---

# ⚡ 16. 30-Second Cheat Sheet

```text
NTDS.dit
→ Active Directory database
→ Usually C:\Windows\NTDS\ntds.dit

PROBLEM
→ File locked while AD DS is running

METHOD 1
→ vssadmin.exe
→ Volume Shadow Copy
→ create shadow

METHOD 2
→ ntdsutil.exe
→ IFM
→ ifm + create

DETECTION
→ Sysmon 1 = Process Creation
→ Sysmon 11 = File Creation
→ 4688 = Windows Process Creation

KEY INDICATORS
→ ntdsutil.exe + ifm + create
→ vssadmin.exe + create shadow
→ ntds.dit
→ SYSTEM
→ HarddiskVolumeShadowCopy

DCSYNC
→ Remote replication
→ Event 4662

NTDS.dit
→ Local database extraction
→ Sysmon 1 / 11

MEMORY
→ DCSync = ASK the DC
→ NTDS.dit = COPY the database
```

# 🎯 Interview Answer

> **NTDS.dit extraction is a credential-access technique where an attacker obtains a copy of the Active Directory database from a Domain Controller. Because the database is normally locked while AD DS is running, attackers may abuse Volume Shadow Copy through `vssadmin` or the IFM functionality of `ntdsutil`. From a SOC perspective, I would monitor Sysmon Event 1 or Windows Event 4688 for suspicious `ntdsutil` and `vssadmin` command lines, and Sysmon Event 11 for `ntds.dit` being written to unusual locations. A shadow copy alone isn't necessarily malicious, so I would correlate it with subsequent access to `NTDS.dit` and the `SYSTEM` hive.**

### 🔥 One-line memory

> **`ntdsutil + IFM/create` OR `vssadmin + create shadow` → investigate → `ntds.dit` creation/access = high-confidence credential extraction.**