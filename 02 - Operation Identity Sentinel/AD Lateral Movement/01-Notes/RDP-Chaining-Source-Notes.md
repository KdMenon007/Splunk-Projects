
## 1. 🎯 RDP in One Sentence

> **RDP gives an attacker an interactive desktop session on a remote Windows machine.**

Unlike PsExec, RDP doesn't normally create a distinctive service or obvious remote-execution artifact.

```text
Compromised workstation
        ↓
      RDP
        ↓
Intermediate server
        ↓
      RDP
        ↓
Domain Controller
```

This is **RDP chaining**.

---

# 2. 🔑 Primary RDP Detection Artifact

## Event 4624

Look at:

```text
Logon_Type = 10
```

### Type 10 = RemoteInteractive

Usually:

```text
RDP
```

Important fields:

```text
User
Logon_Type
Source_Network_Address
Logon_ID
_time
```

### Memory

```text
4624 + Type 10
       ↓
      RDP
```

---

# 3. 🧠 RDP vs SMB vs PsExec

|Technique|Typical Logon Type|Main Artifact|
|---|--:|---|
|SMB|**3**|5140 / 5145|
|PsExec|**3**|7045 + SMB|
|RDP|**10**|4624|
|RDP reconnect|**7**|4624|

### Easy memory

```text
Type 3  → NETWORK
Type 7  → RDP RECONNECT
Type 10 → RDP
```

---

# 4. ⚠️ NLA — Important SOC Trap

Modern Windows commonly uses:

**NLA = Network Level Authentication**

With NLA, you may see:

```text
Type 3
   ↓
seconds later
   ↓
Type 10
```

This does **not necessarily mean**:

```text
SMB/PsExec
+
RDP
```

Instead:

```text
Type 3
 ↓
NLA authentication
 ↓
Type 10
 ↓
RDP session
```

### 🔥 Remember

> **Type 3 immediately followed by Type 10 from the same source can be the NLA prelude to RDP.**

---

# 5. 🟢 Normal vs 🔴 Suspicious RDP

### 🟢 Workstation → Server

Usually normal:

```text
IT Admin Workstation
        ↓
       RDP
        ↓
     Server
```

Typical administrative activity.

---

### 🟡 Workstation → Workstation

Less common:

```text
Workstation
     ↓
    RDP
     ↓
Workstation
```

Could be helpdesk, but investigate the context.

---

### 🔴 Server → Server

Potentially suspicious:

```text
Server A
   ↓ RDP
Server B
```

Servers don't normally need to initiate outbound RDP.

Possible explanation:

> Someone is using Server A as an intermediate pivot point.

⚠️ Not automatically malicious — jump boxes and administrative infrastructure can make this legitimate.

---

# 6. 🎯 Don't Start With "Find All RDP"

RDP can be noisy.

A better SOC approach:

```text
Suspicious activity
      ↓
Find process/session
      ↓
Identify LogonId
      ↓
Correlate 4624
      ↓
Determine Logon Type
      ↓
Find Source IP
      ↓
Identify Source Host
      ↓
Investigate source
```

This is **pivot-based investigation**.

---

# 7. 🔎 Step 1 — Find Suspicious Process

Example: discovery commands executed on a Domain Controller.

```spl
index=win EventCode=1 host=THM-DC
| search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*")
| table _time, host, User, Image, CommandLine, LogonId
| sort _time
```

The important field:

```text
LogonId
```

This tells you which Windows logon session the process belongs to.

---

# 8. 🔗 Step 2 — Correlate LogonId → 4624

Take:

```text
LogonId
```

and search:

```spl
index=win EventCode=4624 host=THM-DC Logon_ID={LOGON_ID}
| table _time, user, Logon_Type, Source_Network_Address, Logon_ID
```

You might discover:

```text
Logon_Type = 10
```

Therefore:

```text
Suspicious process
      ↓
LogonId
      ↓
4624
      ↓
Type 10
      ↓
RDP
```

🔥 You didn't hunt for RDP directly — **the investigation discovered it.**

---

# 9. 🌐 Step 3 — Identify Source IP

From 4624:

```text
Source_Network_Address
```

Example:

```text
10.5.50.25
```

Now ask:

> **Which machine owns this IP?**

---

# 10. 🖥️ Step 4 — IP → Hostname

Use machine-account authentication.

```spl
index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
| stats count by user, Source_Network_Address
| sort -count
```

If you see:

```text
THM-SRV-01$
```

then:

```text
THM-SRV-01$ 
      ↓
THM-SRV-01
```

You've identified the source machine.

---

# 11. 🔎 Step 5 — Find Outbound RDP

If the source is a Windows machine, search for:

```text
mstsc.exe
```

`mstsc.exe` = Windows Remote Desktop Client.

```spl
index=win EventCode=1 host={SOURCE_SERVER} Image="*mstsc.exe*"
| table _time, User, Image, CommandLine, LogonId
| sort _time
```

This can confirm:

```text
Source machine
      ↓
mstsc.exe
      ↓
Outbound RDP
      ↓
Target
```

---

# 12. 🔗 Step 6 — Trace the Previous Hop

Now take the `LogonId` from the `mstsc.exe` event.

Search 4624:

```spl
index=win EventCode=4624 host={SOURCE_SERVER} Logon_ID={LOGON_ID}
| table _time, user, Logon_Type, Source_Network_Address, Logon_ID
```

You may find:

```text
Type 10
Source IP = 10.5.50.10
```

Now you have:

```text
Workstation
    ↓ RDP
Intermediate Server
    ↓ RDP
Domain Controller
```

---

# 13. 🔥 RDP Chaining

## Definition

> **RDP chaining occurs when an attacker uses one compromised/intermediate system to establish another RDP connection to a deeper target.**

Example:

```text
THM-MKT-WS
     │
     │ RDP
     ▼
THM-SRV-01
     │
     │ RDP
     ▼
THM-DC
```

### Why source IP changes

First connection:

```text
THM-MKT-WS
     ↓
THM-SRV-01
```

Second connection:

```text
THM-SRV-01
     ↓
THM-DC
```

The Domain Controller sees:

```text
Source = THM-SRV-01
```

**not the original workstation.**

That's why investigating only the final destination can hide the attacker's original entry point.

---

# 14. 🧠 RDP Chain Investigation Map

```text
DOMAIN CONTROLLER
      │
      │ 4624 Type 10
      │
      ▼
Source IP
      │
      ▼
Machine Account
      │
      ▼
Source Hostname
      │
      ▼
Sysmon Event 1
      │
      ▼
mstsc.exe
      │
      ▼
LogonId
      │
      ▼
4624 on intermediate server
      │
      ▼
Previous Source IP
      │
      ▼
Previous Host
```

You can keep repeating this until you reach the original workstation.

---

# 15. 🧩 Complete Attack Scenario

```text
                COMPROMISED
                WORKSTATION
                    │
                    │ RDP
                    ▼
              INTERMEDIATE
                 SERVER
                    │
                    │ RDP
                    ▼
              DOMAIN CONTROLLER
                    │
                    ▼
          Discovery Commands
                    │
                    ▼
             Sensitive Target
```

### SOC investigation:

```text
Discovery on DC
      ↓
Sysmon 1
      ↓
LogonId
      ↓
4624
      ↓
Type 10
      ↓
Source IP
      ↓
Machine Account
      ↓
Source Host
      ↓
mstsc.exe
      ↓
Previous LogonId
      ↓
Previous 4624
      ↓
Original Workstation
```

---

# 16. 🚨 Strong RDP Indicators

Look more closely when you see:

-  Type 10 from an unusual workstation
    
-  Type 10 from a server
    
-  Server → Server RDP
    
-  RDP to a Domain Controller
    
-  Privileged account used unexpectedly
    
-  RDP outside normal working hours
    
-  Multiple RDP hops
    
-  RDP followed by discovery commands
    
-  RDP followed by credential access
    
-  RDP followed by lateral movement
    

---

# 17. 🆚 SMB vs PsExec vs RDP


| Feature | SMB | PsExec | RDP |
|---|---|---|---|
| Protocol | SMB | SMB + Service | RDP |
| Port | 445 | 445 | 3389 |
| Remote desktop | ❌ | ❌ | ✅ |
| Admin share | Often | ✅ | ❌ |
| Service creation | ❌ | ✅ | ❌ |
| Event 5140 | ✅ | ✅ | ❌ |
| Event 7045 | ❌ | ✅ | ❌ |
| 4624 Type 3 | ✅ | ✅ | NLA may |
| 4624 Type 10 | ❌ | ❌ | ✅ |
| `mstsc.exe` | ❌ | ❌ | ✅ |
| Interactive session | ❌ | Command shell | ✅ |

---

# 🧠 18. Must-Memorize

```text
RDP
 ↓
4624
 ↓
Type 10
 ↓
RemoteInteractive
```

```text
NLA
 ↓
Type 3
 ↓
Type 10
```

```text
RDP Client
 ↓
mstsc.exe
```

```text
RDP chaining
 ↓
Host A
 ↓
RDP
 ↓
Host B
 ↓
RDP
 ↓
Host C
```

---

# 🎯 Interview-Ready Answer

> **For RDP lateral movement, my primary destination-side artifact is Windows Security Event 4624 with Logon Type 10, which represents a RemoteInteractive logon. I would examine the source IP, account, timestamp and Logon ID. If the activity came from a server or an unusual workstation, I would investigate further. I can use the source IP and machine-account logons to identify the source hostname, then look for mstsc.exe in Sysmon Event 1 to confirm an outbound RDP connection. By correlating Logon IDs across systems, I can identify RDP chaining and trace the attack back toward the original compromised workstation. I would also account for NLA, where a Type 3 logon can appear immediately before the Type 10 RDP logon.**

## 🔥 One-line memory

> **4624 Type 10 → find Source IP → map IP to Host → find mstsc.exe → correlate LogonId → trace the RDP chain backward.**