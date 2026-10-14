
## 1. What is LSASS?

**LSASS = Local Security Authority Subsystem Service**

- Windows process: `lsass.exe`
    
- Responsible for authentication and security-related operations.
    
- Stores authentication material for users who have authenticated to the machine.
    
- Attackers target LSASS because credentials may be available **directly in memory**.
    
- Unlike Kerberoasting/AS-REP Roasting, the attacker doesn't necessarily need to crack anything.
    

```text
Domain Admin logs into workstation
            ↓
Credentials/tickets exist in LSASS
            ↓
Attacker gains access to workstation
            ↓
LSASS dumping
            ↓
Credential material obtained
            ↓
Privilege escalation / lateral movement
```

---

## 2. What Can LSASS Store?

|Credential / Data|Purpose / Risk|
|---|---|
|**NTLM hashes**|Can potentially be used for Pass-the-Hash|
|**Kerberos TGTs**|Can potentially be used for Pass-the-Ticket|
|**Kerberos TGS tickets**|Service authentication|
|**Plaintext passwords**|Possible with WDigest configurations|
|**Cached credentials**|Offline authentication-related material|

### Important

If a **Domain Admin** has an active session on the machine:

```text
DA session
   ↓
Credentials/tickets in LSASS
   ↓
LSASS dump
   ↓
High-value credential theft
```

---

# 3. Why LSASS Is Important

### Kerberoasting

```text
TGS
 ↓
Offline cracking
 ↓
Password
```

### AS-REP Roasting

```text
AS-REP
 ↓
Offline cracking
 ↓
Password
```

### LSASS Dumping

```text
LSASS memory
 ↓
Credential material
 ↓
No cracking necessarily required
```

### Memory trick

> **Roasting = crack ticket material**  
> **LSASS dumping = steal credential material from memory**

---

# 4. Main Detection

## Sysmon Event 10

**Event 10 = ProcessAccess**

Generated when one process opens/accesses another process.

For LSASS detection:

```text
Source Process
      ↓
Accesses
      ↓
lsass.exe
```

### Detection condition

```text
Sysmon Event 10
+
TargetImage = lsass.exe
```

---

# 5. ⚠️ Sysmon Configuration Requirement

Event 10 is **not automatically available** in every Sysmon deployment.

Sysmon must have a `ProcessAccess` rule configured for LSASS.

```text
No ProcessAccess rule
        ↓
No Event 10
        ↓
LSASS dumping may be invisible
```

### SOC lesson

> Always verify telemetry coverage before assuming an attack would generate an event.

---

# 6. Important Event 10 Fields

|Field|Meaning|SOC Importance|
|---|---|---|
|`SourceImage`|Process accessing LSASS|Identify source process|
|`SourceUser`|Account running source process|Identify compromised account|
|`TargetImage`|Target process|Confirm `lsass.exe`|
|`GrantedAccess`|Requested access rights|Identify suspicious memory access|
|`CallTrace`|DLL/API call chain|Identify dumping/injection method|

### Memory trick

```text
WHO    → SourceUser
WHAT   → SourceImage
TARGET → TargetImage
ACCESS → GrantedAccess
METHOD → CallTrace
```

---

# 7. Detection Query — Start Broad

```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe"
| stats count by SourceImage, GrantedAccess
```

### Why start broad?

Don't immediately search for:

```text
0x1010
0x1FFFFF
```

First identify **everything accessing LSASS**.

Then determine:

```text
Normal
   ↓
Baseline
   ↓
Suspicious
   ↓
Investigate
```

---

# 8. GrantedAccess

`GrantedAccess` is a **hexadecimal bitmask**.

Important values:

|Access Right|Hex|Meaning|
|---|--:|---|
|`PROCESS_QUERY_LIMITED_INFORMATION`|`0x1000`|Query basic process information|
|`PROCESS_QUERY_INFORMATION`|`0x0400`|Query detailed process information|
|`PROCESS_VM_READ`|`0x0010`|Read process memory|
|`PROCESS_ALL_ACCESS`|`0x1FFFFF`|Full process access|

---

# 9. Most Important Access Value

```text
0x0010
```

=

**PROCESS_VM_READ**

Why important?

```text
VM_READ
 ↓
Read LSASS memory
 ↓
Potential credential extraction
```

---

# 10. Understanding `0x1010`

```text
0x1010
```

is composed of:

```text
0x1000
+
0x0010
=
0x1010
```

So:

```text
0x1000 → Query limited information
0x0010 → Read process memory
```

### Important

The `0x0010` portion is particularly relevant for credential dumping.

---

# 11. Common Access Masks

```text
0x1010
→ Query + VM Read

0x1FFFFF
→ PROCESS_ALL_ACCESS
```

The access mask **alone does not prove malicious activity**.

Always investigate:

```text
SourceImage
+
Full path
+
SourceUser
+
CallTrace
+
GrantedAccess
```

---

# 12. CallTrace

`CallTrace` shows the chain of DLLs/functions involved in the process access.

It can help distinguish different LSASS access techniques.

### MiniDump-style

Look for:

```text
dbgcore.dll
dbghelp.dll
```

Possible indication:

```text
MiniDump API
 ↓
ProcDump / comsvcs.dll style dumping
```

---

# 13. Injection-Based Access

CallTrace may contain:

```text
UNKNOWN(...)
UNKNOWN(...)
```

This can indicate memory addresses that aren't mapped to known DLLs.

Potentially associated with:

- Injected shellcode
    
- In-memory implants
    
- C2 frameworks
    
- Process injection
    

### Important

```text
Known DLLs
→ MiniDump-style

UNKNOWN offsets
→ Possible injected code
```

---

# 14. Example — MiniDump CallTrace

```text
C:\Windows\SYSTEM32\ntdll.dll+9D4C4|
C:\Windows\System32\KERNELBASE.dll+2B16D|
C:\Windows\System32\dbgcore.dll+A3C8|
...
```

### Interpretation

Known system DLLs including:

```text
dbgcore.dll
```

suggest MiniDump-style access.

---

# 15. Example — Injection CallTrace

```text
C:\Windows\SYSTEM32\ntdll.dll+9D4C4|
UNKNOWN(0000025FA0120000)|
UNKNOWN(0000025FA0124B30)|
...
```

### Interpretation

`UNKNOWN` memory regions may indicate injected code accessing LSASS.

---

# 16. Investigate the Suspicious Process

After identifying the suspicious `SourceImage`:

```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe" SourceImage={SUSPICIOUS_PROCESS}
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
```

Investigate:

- `SourceImage`
    
- `SourceUser`
    
- `GrantedAccess`
    
- `CallTrace`
    
- Full executable path
    
- Parent process
    
- Host
    
- Timeline
    

---

# 17. SourceUser — Critical Field

### Example 1

```text
SourceUser = NT AUTHORITY\SYSTEM
```

Could indicate:

- Service
    
- Scheduled task
    
- SYSTEM-level execution
    

Still investigate.

### Example 2

```text
SourceUser = DOMAIN\jsmith
```

More concerning.

Potentially indicates:

```text
Compromised domain account
        ↓
Attacker execution
        ↓
LSASS access
```

### SOC priority

> Identify **who executed the process**.

---

# 18. Normal LSASS Access

Some legitimate Windows processes access LSASS.

Examples:

|Process|Typical Access|
|---|---|
|`C:\Windows\System32\csrss.exe`|`0x1000` / `0x1400`|
|`C:\Windows\System32\WerFault.exe`|`0x1000`|
|`C:\Windows\System32\svchost.exe`|`0x1010`|
|AV/EDR agents|Varies|

Therefore:

```text
Event 10 + lsass.exe
≠
Automatically malicious
```

---

# 19. 🚨 Full Path Is Critical

Never trust only the process name.

### Potentially legitimate

```text
C:\Windows\System32\svchost.exe
```

### Suspicious

```text
C:\Users\Public\svchost.exe
```

or:

```text
C:\Temp\svchost.exe
```

An attacker can simply name malware:

```text
svchost.exe
```

### SOC rule

> **Validate the complete `SourceImage` path, not just the filename.**

---

# 20. Detection Logic

```text
Event 10
   ↓
Target = lsass.exe
   ↓
Identify SourceImage
   ↓
Check FULL path
   ↓
Check SourceUser
   ↓
Check GrantedAccess
   ↓
Check CallTrace
   ↓
Check Parent Process
   ↓
Check timeline
   ↓
Determine legitimate vs suspicious
```

---

# 21. Strong Suspicion Pattern

```text
Sysmon 10
+
Target = lsass.exe
+
Unusual SourceImage
+
Non-standard path
+
VM_READ / high access
+
Suspicious CallTrace
+
Unexpected SourceUser
```

🚨 **High-confidence LSASS dumping suspicion**

---

# 22. Other Credential Stores

|Store|Contains|Scope|
|---|---|---|
|**LSASS**|Live authentication material|Current machine|
|**SAM**|Local account hashes|Current machine|
|**Cached credentials**|Cached domain logon material|Current machine|
|**NTDS.dit**|AD account database/hashes|Entire domain|

---

# 23. SAM

Location:

```text
C:\Windows\System32\config\SAM
```

Contains:

> Local account password hashes.

### Important

SAM does **not** contain the entire domain's credentials.

```text
SAM
 ↓
Local accounts
```

---

# 24. Cached Domain Credentials

Stored in the Windows registry security cache.

Purpose:

> Allow domain users to authenticate when the domain controller isn't reachable.

Characteristics:

- Designed for offline logon.
    
- Slow to crack.
    
- Not directly usable for traditional Pass-the-Hash.
    
- Generally lower priority than live LSASS credentials for domain compromise.
    

---

# 25. NTDS.dit

Located on Domain Controllers:

```text
C:\Windows\NTDS\ntds.dit
```

Contains:

> Active Directory database and credential information for domain accounts.

### Scope

```text
LSASS
→ Current machine

NTDS.dit
→ Domain-wide account database
```

---

# 26. Why LSASS Is Especially Valuable

Suppose:

```text
Domain Admin
    ↓
Logs into workstation
    ↓
Active session
    ↓
Credentials/tickets in LSASS
```

Attacker dumps LSASS:

```text
LSASS
 ↓
DA credential material
 ↓
Lateral movement
 ↓
Potential domain compromise
```

This is why defenders care about **where privileged accounts log in**.

---

# 27. LSASS → Pass-the-Hash / Pass-the-Ticket

Credentials obtained from LSASS can potentially support:

### Pass-the-Hash

```text
NTLM hash
 ↓
Authentication
 ↓
Lateral movement
```

### Pass-the-Ticket

```text
Kerberos ticket
 ↓
Ticket reuse
 ↓
Lateral movement
```

The important distinction:

> **LSASS dumping is the credential-theft technique; Pass-the-Hash / Pass-the-Ticket are potential follow-on techniques.**

---

# 🎯 28. SOC L1 Investigation Checklist

```markdown
- [ ] Confirm Sysmon Event 10
- [ ] Confirm TargetImage = lsass.exe
- [ ] Identify SourceImage
- [ ] Validate FULL SourceImage path
- [ ] Identify SourceUser
- [ ] Examine GrantedAccess
- [ ] Look for PROCESS_VM_READ (0x0010)
- [ ] Examine CallTrace
- [ ] Check for dbgcore.dll / dbghelp.dll
- [ ] Check for UNKNOWN memory offsets
- [ ] Identify parent process
- [ ] Determine whether source process is legitimate
- [ ] Check host timeline
- [ ] Check for other suspicious activity
- [ ] Investigate compromised account if applicable
- [ ] Escalate based on confidence and privilege
```

---

# ⚡ 29. LSASS — 30-Second Cheat Sheet

```text
LSASS
→ Local Security Authority Subsystem Service

TARGET
→ lsass.exe

DETECTION
→ Sysmon Event 10

IMPORTANT FIELDS
→ SourceImage
→ SourceUser
→ TargetImage
→ GrantedAccess
→ CallTrace

IMPORTANT ACCESS
→ 0x0010 = PROCESS_VM_READ
→ 0x1010 = Query + VM Read
→ 0x1FFFFF = ALL ACCESS

CALLTRACE
→ dbgcore.dll / dbghelp.dll
   = MiniDump-style

→ UNKNOWN offsets
   = Possible injection

NORMAL PROCESSES
→ csrss.exe
→ WerFault.exe
→ svchost.exe
→ AV/EDR

CRITICAL RULE
→ Check FULL PATH

KEY QUESTION
→ Who accessed LSASS, from where,
  with what access, and why?
```

---

# 🧠 30. Interview Answer

> **LSASS dumping is an endpoint credential-theft technique where an attacker accesses the memory of `lsass.exe` to obtain authentication material such as NTLM hashes and Kerberos tickets. I would detect it primarily using Sysmon Event 10, looking for processes accessing `lsass.exe`. I would investigate the `SourceImage`, full executable path, `SourceUser`, `GrantedAccess`, and `CallTrace`. `PROCESS_VM_READ` (`0x0010`) is particularly relevant because it allows reading process memory. I would also distinguish legitimate system or security processes from suspicious processes based on their full path and execution context.**