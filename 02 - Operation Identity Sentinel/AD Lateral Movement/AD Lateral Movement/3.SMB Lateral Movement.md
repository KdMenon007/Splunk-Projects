
## 1. 🎯 SMB in Lateral Movement

**SMB = Server Message Block**

- **Port:** `445/TCP`
    
- Used for:
    
    - File sharing
        
    - Network drives
        
    - Shared documents
        
    - Network printers
        
    - Administrative shares
        
    - Remote management/RPC-related activity
        

### Why attackers like SMB

```text
SMB
 ↓
Extremely common
 ↓
Lots of legitimate traffic
 ↓
Attack traffic can blend in
```

> **SMB is powerful for attackers — and noisy for defenders.**

---

# 2. 🔐 Windows Administrative Shares

Windows automatically creates several hidden administrative shares.

|Share|Purpose|
|---|---|
|`C$`|Root of C: drive|
|`D$`|Root of D: drive|
|`E$`|Root of E: drive|
|`ADMIN$`|Windows directory|
|`IPC$`|Inter-Process Communication / named pipes|

### Remember

```text
C$      → C:\

ADMIN$  → C:\Windows

IPC$    → IPC / named pipes / RPC
```

---

# 3. 🚨 Why Admin Shares Matter

Normal users typically access:

```text
\\server\Marketing
\\server\Shared
\\server\IT
```

Attackers/admins may access:

```text
\\server\C$
\\server\ADMIN$
\\server\IPC$
```

Therefore:

> **ADMIN$ / C$ access deserves investigation, but isn't automatically malicious.**

An IT administrator performing maintenance can legitimately access them.

---

# 4. 🧠 Key Detection Events

|Event|What it tells you|Location|
|---|---|---|
|**5140**|Network share accessed|Destination|
|**4624**|Successful authentication|Destination|
|**4648**|Explicit credentials used|Source|
|**Sysmon 1**|Process created|Source|

### Memory

```text
5140 → SHARE
4624 → LOGIN
4648 → EXPLICIT CREDS
Sysmon 1 → COMMAND/PROCESS
```

---

# 5. 🔎 Event 5140 — Your Starting Point

Event 5140:

> **A network share object was accessed.**

Useful fields:

```text
host
Source_Address
user
Share_Name
_time
```

### What each field means

```text
host
 ↓
Target server

Source_Address
 ↓
Where connection came from

user
 ↓
Credentials/account used

Share_Name
 ↓
Which share was accessed
```

---

# 6. 🔥 Hunt for Admin Shares

```spl
index=win EventCode=5140 Share_Name IN ("*\\ADMIN$\*", "*\\C$\*")
| table _time, host, Source_Address, user, Share_Name
| sort _time
```

### Look for:

```text
One source IP
      ↓
ADMIN$
      ↓
Multiple destination machines
      ↓
Short time period
```

🚨 **Strong lateral movement indicator.**

---

# 7. 🧪 Suspicious Pattern

Example:

```text
10.5.50.99
     │
     ├── ADMIN$ → SERVER01
     ├── ADMIN$ → SERVER02
     ├── ADMIN$ → SERVER03
     └── ADMIN$ → WORKSTATION04
```

Especially suspicious if:

- Source is a normal workstation
    
- User doesn't normally administer servers
    
- Activity occurs outside normal hours
    
- Many hosts are accessed rapidly
    
- Privileged credentials are involved
    

---

# 8. 🟢 Baseline Is Everything

Finding:

```text
ADMIN$ access
```

isn't enough.

Ask:

> **"Does this user normally do this?"**

### Baseline query

```spl
index=win EventCode=5140 user={USER_ACCOUNT}
| table _time, Source_Address, Share_Name, host
| sort _time
```

Compare:

```text
NORMAL
IT user
    ↓
IT workstation
    ↓
IT share
```

against:

```text
SUSPICIOUS
IT credentials
    ↓
Marketing workstation
    ↓
ADMIN$
    ↓
10 servers
    ↓
5 minutes
```

🔥 **The second pattern is far more concerning.**

---

# 9. 🧭 Trace the Source IP → Hostname

You have:

```text
Source_Address = 10.x.x.x
```

But you need:

```text
Source_Address
      ↓
Hostname
      ↓
Investigate source machine
```

### Useful AD clue

Computer accounts normally end with:

```text
$
```

Example:

```text
THM-MKT-WS$
```

Therefore, search 4624:

```spl
index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
| stats count by user, Source_Network_Address
| sort -count
```

If you get:

```text
THM-MKT-WS$
```

then:

```text
THM-MKT-WS$ 
     ↓
THM-MKT-WS
```

You now have the source hostname.

---

# 10. 🕵️ Pivot to the Source Machine

Now search Sysmon Event 1.

```spl
index=win EventCode=1 host={SOURCE_HOST} CommandLine="*ADMIN$*"
| table _time, User, Image, CommandLine
| sort _time
```

This can reveal:

```text
User
 ↓
Who was actually logged in / running the process

Image
 ↓
What executable ran

CommandLine
 ↓
What they attempted to access
```

---

# 11. 🔥 The Most Important Correlation

Imagine:

```text
User field:
michelle.smith
```

but:

```text
CommandLine:
... /user:luke.sullivan ...
```

Now you have:

```text
PERSON AT KEYBOARD
        ↓
michelle.smith

CREDENTIAL BEING USED
        ↓
luke.sullivan
```

🚨 That's a **major credential misuse indicator**.

### Memorize:

> **User ≠ credential used**

This distinction is extremely important during lateral-movement investigations.

---

# 12. 🔗 Full Investigation Chain

This is the workflow you should memorize for SOC interviews:

```text
          EVENT 5140
              ↓
    Suspicious ADMIN$/C$
              ↓
     Identify Source IP
              ↓
          EVENT 4624
              ↓
   Map IP → Machine Account
              ↓
       Identify Hostname
              ↓
        Pivot to Source
              ↓
        SYSMON EVENT 1
              ↓
      Find ADMIN$ command
              ↓
       Identify User
              ↓
    Identify credentials
              ↓
         EVENT 4648
              ↓
       Confirm explicit
       credential usage
              ↓
       Correlate source
       + destination
              ↓
        🚨 Investigate
```

---

# 13. ⚠️ Important Detection Gap

Don't assume:

```text
No Sysmon Event 1
        ↓
No lateral movement
```

❌ Wrong.

Attackers can use tools/frameworks that establish SMB connections without spawning `net.exe`.

Examples include:

```text
Cobalt Strike
Metasploit
```

In those cases:

```text
Sysmon 1
   ↓
May not show net.exe

BUT

4648
   ↓
May still show explicit credential usage

5140
   ↓
Still appears on destination
```

### Golden rule

> **Absence of a process-creation event does not prove absence of SMB lateral movement.**

---

# 14. 🧩 Source vs Destination

|Evidence|Source|Destination|
|---|:-:|:-:|
|Event 4648|✅|❌|
|Sysmon 1|✅|Depends on execution|
|Event 4624|❌*|✅|
|Event 5140|❌|✅|
|Source IP|—|✅|
|Target server|4648 can show it|Host identifies it|
|Account used|4648|4624|

*For this investigation model, focus on the destination-side 4624.

---

# 15. 🚨 High-Confidence Suspicious Pattern

```text
Normal workstation
       ↓
Privileged credentials
       ↓
ADMIN$
       ↓
Multiple servers
       ↓
Rapid connections
       ↓
Unusual time
       ↓
User ≠ credential owner
       ↓
4648 + 5140 correlation
       ↓
🚨 HIGH PRIORITY
```

---

# 16. 🛡️ SOC Investigation Questions

When you see suspicious SMB activity, ask:

### SOURCE

-  What IP initiated the connection?
    
-  What hostname owns that IP?
    
-  Is this a normal administrative workstation?
    

### USER

-  Which account authenticated?
    
-  Is the account privileged?
    
-  Does this account normally access these systems?
    

### SHARE

-  `ADMIN$`?
    
-  `C$`?
    
-  `IPC$`?
    
-  Normal business share?
    

### TIME

-  Business hours?
    
-  Weekend?
    
-  Unusual time?
    

### BEHAVIOR

-  One server?
    
-  Multiple servers?
    
-  Rapid connections?
    
-  Repeated access?
    

### SOURCE PROCESS

-  What process initiated the connection?
    
-  Is Sysmon Event 1 available?
    
-  Is there an Event 4648?
    
-  Does the logged-in user differ from the credential used?
    

---

# 🧠 17. Ultimate SMB Memory Map

```text
                    SMB
                 TCP/445
                    │
          ┌─────────┴─────────┐
          │                   │
       LEGITIMATE          ATTACK
          │                   │
   File sharing          Admin shares
   Printers              C$
   GPO                    ADMIN$
   Backups               IPC$
          │                   │
          └─────────┬─────────┘
                    ↓
                EVENT 5140
                    ↓
             What share?
                    ↓
              Source IP
                    ↓
              EVENT 4624
                    ↓
           IP → hostname
                    ↓
             SOURCE HOST
                    ↓
             SYSMON 1
                    ↓
             EVENT 4648
                    ↓
       Who was at keyboard?
                    ↓
       Whose credentials used?
                    ↓
                CONTEXT
                    ↓
             🚨 Verdict
```

## 🔥 10 Things to Memorize

```text
1. SMB = TCP/445

2. ADMIN$ = Windows directory

3. C$ = C:\

4. IPC$ = IPC / named pipes

5. 5140 = network share access

6. 4624 = successful authentication

7. 4648 = explicit credentials

8. Sysmon 1 = process creation

9. User ≠ credential used can indicate credential misuse

10. One source → many ADMIN$ targets = investigate
```

### 🎯 Interview-ready answer

> **For SMB lateral movement, I would start with Event 5140 to identify access to sensitive administrative shares such as ADMIN$ and C$. I would examine the source address, destination host, account and timing, then baseline the user's normal behavior. Next, I'd map the source IP to a hostname using machine-account authentication events and pivot to that source host. Sysmon Event 1 can reveal the process and command used, while Event 4648 can confirm explicit credential usage. Finally, I'd correlate source and destination evidence and determine whether the activity fits the user's normal administrative behavior.**