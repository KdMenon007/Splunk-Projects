
## 1. 🎯 Why Discovery?

**Goal:** Understand the AD environment before lateral movement.

Attackers want to discover:

- 👤 Users
    
- 👑 Privileged groups
    
- 🖥️ Computers
    
- 🏢 Domain Controllers
    
- 🔗 Domain trusts
    
- 📁 Network shares
    
- 🔐 Local administrators
    

**Mental model:**

> **Discover → Identify valuable targets → Find path → Move laterally**

---

## 2. 🔎 Windows AD Discovery Commands

|Purpose|Command|What it reveals|
|---|---|---|
|Domain Controllers|`nltest /dclist:domain`|Domain Controllers|
|Domain Trusts|`nltest /domain_trusts`|Trusted domains|
|Domain Users|`net user /domain`|Domain accounts|
|Domain Admins|`net group "Domain Admins" /domain`|Domain Admin members|
|Enterprise Admins|`net group "Enterprise Admins" /domain`|Enterprise Admin members|
|Local Admins|`net localgroup administrators`|Local administrators|
|Network Systems|`net view`|Visible computers|
|Remote Shares|`net view \\THM-SHR-SRV /all`|Shares on target|
|AD Users|`Get-ADUser -Filter *`|AD users|
|AD Group Members|`Get-ADGroupMember "Domain Admins"`|Privileged members|
|AD Computers|`Get-ADComputer -Filter *`|Domain computers|

### 🔥 Remember

```text
nltest  → Domain / Trust
net     → Users / Groups / Systems / Shares
Get-AD* → PowerShell AD enumeration
```

---

# 3. 🧰 Third-Party Discovery Tools

### `adfind.exe`

Used for detailed AD enumeration.

Known to have been used by ransomware groups.

### `dsquery`

LDAP/AD query utility.

### PowerShell DirectorySearcher

```powershell
[System.DirectoryServices.DirectorySearcher]
```

Can perform raw LDAP queries.

---

# 4. 🕵️ Why This Works Without Admin

A normal authenticated domain user can generally **read a large amount of AD information by default**.

So:

```text
Compromised HR account
        ↓
Authenticated domain user
        ↓
Query AD
        ↓
Users + Groups + Computers + Trusts
        ↓
Plan lateral movement
```

⚠️ **Important SOC point:**

> Discovery does NOT automatically mean compromise.

You need **context**.

A domain admin using `net user /domain` may be completely normal.

A marketing workstation suddenly executing:

```cmd
nltest /domain_trusts
net group "Domain Admins" /domain
net view
```

is much more interesting.

---

# 5. 📊 Key Windows Logs

## Sysmon Event ID 1

### Process Creation

Captures:

- Process
    
- User
    
- Host
    
- Command line
    
- Parent process
    
- Timestamp
    

Example:

```text
powershell.exe
cmd.exe
nltest.exe
net.exe
```

### Important fields

```text
_time
host
User
Image
CommandLine
ParentImage
```

---

# 6. 🟦 PowerShell Event ID 4104

## Script Block Logging

Captures PowerShell script content executed inside a PowerShell session.

Useful for detecting:

```powershell
Get-ADUser
Get-ADGroupMember
Get-ADComputer
```

### Why 4104 matters

Sysmon Event 1 may show:

```text
powershell.exe
```

But 4104 can reveal:

```powershell
Get-ADUser -Filter *
Get-ADGroupMember "Domain Admins"
```

So:

> **Event 1 = process launched**  
> **Event 4104 = PowerShell script executed**

---

# 7. 🔍 Splunk — Sysmon Discovery Hunt

```spl
index=win EventCode=1
| search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*", "*net * localgroup*")
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

### What you're looking for

```text
Time
 ↓
Host
 ↓
User
 ↓
Process
 ↓
CommandLine
 ↓
Parent process
```

Ask:

**WHO** executed it?

**WHERE**?

**WHEN**?

**WHAT** command?

**FROM WHICH parent process?**

**IS IT NORMAL FOR THIS USER/HOST?**

---

# 8. 🟪 Splunk — PowerShell Discovery Hunt

```spl
index=win EventCode=4104
| search Message IN ("*Get-ADUser*", "*Get-ADGroupMember*", "*Get-ADComputer*")
| table _time, Message
| sort _time
```

### Important field

```text
Message
```

Contains the PowerShell script block.

---

# 9. 🧠 Event 1 vs Event 4104

|Feature|Sysmon 1|PowerShell 4104|
|---|---|---|
|Process creation|✅|❌|
|Command line|✅|Sometimes|
|PowerShell executable|✅|❌|
|PowerShell cmdlet|Not always|✅|
|Script content|❌|✅|
|Interactive PowerShell commands|Limited|✅|
|Encoded PowerShell|Shows encoded command|Can reveal decoded script|

### Golden rule

```text
Sysmon 1
   ↓
"What process started?"

4104
   ↓
"What PowerShell code actually executed?"
```

---

# 10. 🚨 Detection Logic

Don't alert simply because:

```text
net user /domain
```

was executed.

Instead investigate the **combination of signals**.

### Suspicious pattern

```text
Unusual workstation
        +
Unusual user
        +
Unusual time
        +
Multiple AD discovery commands
        +
PowerShell discovery
        +
Suspicious parent process
        =
🚨 HIGHER PRIORITY INVESTIGATION
```

---

# 11. 🧩 Example Attack Chain

```text
Initial Access
      ↓
Compromised user account
      ↓
AD Discovery
      ↓
net user /domain
      ↓
net group "Domain Admins" /domain
      ↓
nltest /domain_trusts
      ↓
Get-ADComputer -Filter *
      ↓
Identify privileged target
      ↓
Lateral Movement
```

---

# 12. 🥷 Living Off The Land — LOTL

**LOTL = Living Off The Land**

Attackers use legitimate Windows utilities already present on the machine.

Examples:

```text
net.exe
nltest.exe
wmic.exe
netsh.exe
powershell.exe
cmd.exe
```

### Why attackers like LOTL

- No custom malware required
    
- Tools already exist
    
- Can blend into administrative activity
    
- May bypass simplistic application-based detections
    
- Less suspicious than dropping an unknown executable
    

### SOC mindset

> **"Signed/legitimate binary" ≠ "legitimate activity."**

---

# 13. 🧪 Obfuscation

Attackers may try to hide discovery commands.

Example:

```powershell
powershell -enc <Base64>
```

or command-line escaping.

### Detection difference

```text
Encoded PowerShell
       ↓
Sysmon Event 1
       ↓
May show encoded command

PowerShell 4104
       ↓
Can capture processed/decoded script
```

Therefore:

> **4104 can be extremely valuable for PowerShell hunting.**

---

# 14. 🧠 SOC Analyst Investigation Checklist

When you see AD discovery:

-  Identify the user
    
-  Identify the workstation
    
-  Check timestamp
    
-  Check command line
    
-  Check parent process
    
-  Look for multiple discovery commands
    
-  Check whether the user normally performs administrative activity
    
-  Check whether the workstation is an admin/server workstation
    
-  Search for PowerShell 4104 events
    
-  Search for additional suspicious processes
    
-  Look for credential access
    
-  Look for lateral movement afterward
    
-  Check authentication events around the same time
    
-  Determine whether activity is legitimate administrative work
    

---

# 🔥 15. Commands You MUST Memorize

```text
nltest /dclist:domain
        ↓
Find Domain Controllers

nltest /domain_trusts
        ↓
Find trusted domains

net user /domain
        ↓
Find domain users

net group "Domain Admins" /domain
        ↓
Find Domain Admins

net group "Enterprise Admins" /domain
        ↓
Find Enterprise Admins

net localgroup administrators
        ↓
Find local admins

net view
        ↓
Find visible systems

net view \\SERVER /all
        ↓
Find remote shares
```

### PowerShell

```powershell
Get-ADUser -Filter *
Get-ADGroupMember "Domain Admins"
Get-ADComputer -Filter *
```

---

# 🎯 Interview Memory Trick

```text
DOMAIN
 ├── nltest → DCs + Trusts
 │
USERS/GROUPS
 ├── net user
 ├── net group
 └── Get-ADUser / Get-ADGroupMember
 │
SYSTEMS
 ├── net view
 └── Get-ADComputer
 │
DETECTION
 ├── Sysmon 1 → Process creation
 └── 4104 → PowerShell script blocks
```

## 💡 One-line interview answer

> **AD discovery is the reconnaissance phase where an attacker enumerates domain users, privileged groups, domain controllers, trusts, computers and shares to understand the environment and identify targets for lateral movement. From a SOC perspective, I would correlate Sysmon Event 1 and PowerShell Event 4104 with user, host, parent process, timing and surrounding authentication activity rather than treating a single discovery command as malicious.**