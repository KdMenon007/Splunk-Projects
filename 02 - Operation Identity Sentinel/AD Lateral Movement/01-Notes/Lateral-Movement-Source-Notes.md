
## 1. 🎯 What Is Lateral Movement?

After discovery, the attacker knows:

- 🖥️ Which machines exist
    
- 👤 Which accounts exist
    
- 👑 Which accounts have privileges
    
- 🎯 Which servers are valuable
    

Now they move from the **initially compromised system → another system**.

### Core pattern

```text
DISCOVERY
    ↓
Find valuable target
    ↓
Obtain/use credentials
    ↓
AUTHENTICATE
    ↓
EXECUTE
    ↓
DESTINATION
    ↓
Repeat
```

### 🔥 Golden rule

> **Lateral movement = Authenticate → Execute**

The exact technique may change, but this pattern remains.

---

# 2. 🧭 Source vs Destination

Every remote connection creates artifacts on **two machines**.

```text
SOURCE MACHINE                         DESTINATION
     │                                      │
     │  Remote authentication               │
     ├─────────────────────────────────────►│
     │                                      │
     │                                      │
  Attacker                                Target
  initiates                              receives
```

### Source tells you:

- Who initiated the connection
    
- Which credentials were used
    
- Which target was selected
    
- What process initiated it
    

### Destination tells you:

- Who authenticated
    
- Whether authentication succeeded
    
- How they connected
    
- What happened after authentication
    

### SOC rule

```text
SOURCE = Where did it come from?
DESTINATION = What happened there?
```

**Best investigations correlate both sides.**

---

# 3. 🔑 Most Important Windows Events

|Event|Meaning|Where?|
|---|---|---|
|**4624**|Successful logon|Destination|
|**4648**|Explicit credentials used|Source|
|**5140**|Network share accessed|Destination|
|**Sysmon 1**|Process creation|Source/host where process ran|

### Memorize this

```text
4648 → SOURCE
4624 → DESTINATION
5140 → SHARE ACCESS
Sysmon 1 → PROCESS
```

---

# 4. 🚪 Event 4624 — Successful Logon

Event **4624** is generated on the **destination** when authentication succeeds.

The key field:

```text
Logon Type
```

---

# 5. 🧠 Logon Types You Must Know

|Logon Type|Meaning|Common use|
|--:|---|---|
|**3**|Network|SMB, PsExec|
|**7**|Unlock / reconnect|RDP reconnect|
|**10**|RemoteInteractive|RDP|

### Easy memory trick

```text
3  → NETWORK
7  → RECONNECT
10 → RDP
```

---

# 6. 🟦 Logon Type 3

```text
Logon Type = 3
```

Means:

> **Network logon**

Commonly associated with:

- SMB
    
- PsExec
    
- Remote administrative access
    

⚠️ **Important:**

Type 3 alone doesn't tell you exactly which lateral movement technique was used.

For example:

```text
SMB        → Type 3
PsExec     → Type 3
```

Therefore:

> **Type 3 requires additional artifacts.**

Look at:

```text
4624
+
5140
+
Sysmon 1
+
4648
```

---

# 7. 🟩 Logon Type 10

```text
Logon Type = 10
```

Means:

> **RemoteInteractive**

Typically:

```text
RDP
```

So:

```text
4624 + Type 10
        ↓
Likely RDP
```

---

# 8. 🟨 Logon Type 7 — Important Trap

Type 7 means:

> **Unlock / reconnect**

It can occur when an RDP connection reconnects to an existing session.

Example:

```text
Attacker connects via RDP
        ↓
Existing RDP session exists
        ↓
Windows reconnects to it
        ↓
Logon Type 7
```

Therefore:

### ❌ Don't hunt only for:

```text
Logon_Type=10
```

### Also investigate:

```text
Logon_Type=7
```

especially when:

```text
Remote IP != 127.0.0.1
```

That can indicate a remote RDP reconnection rather than a physical/local unlock.

---

# 9. ⚠️ Logon ID Correlation Trap

An RDP session can persist across disconnect/reconnect.

A reconnection can create a **new Logon ID**, even though the underlying RDP session continues.

Therefore:

> **Don't rely exclusively on Logon_ID correlation across RDP disconnect/reconnect boundaries.**

Use additional context:

```text
User
+
Source IP
+
Destination
+
Timestamp
+
Logon Type
```

---

# 10. 🔥 Event 4648 — Explicit Credentials

Event **4648**:

> **A process used credentials different from those of the currently logged-in user.**

This is extremely useful for tracing the **source**.

Example concept:

```text
Logged-in user:
liam.patel

Uses:
luke.sullivan

To access:
THM-SHR-SRV
```

Event 4648 can tell you:

```text
Original User
      ↓
Alternate Credentials
      ↓
Target Server
```

---

# 11. 🧪 Example

Suppose:

```cmd
net use \\THM-SHR-SRV\ADMIN$ /user:luke.sullivan
```

Source machine:

```text
THM-MKT-WS
```

Logged-in user:

```text
liam.patel
```

Credentials used:

```text
luke.sullivan
```

Target:

```text
THM-SHR-SRV
```

### Source-side evidence

```text
4648
 ↓
liam.patel
 ↓
used luke.sullivan
 ↓
target THM-SHR-SRV
```

Then destination:

```text
4624
 ↓
luke.sullivan authenticated
 ↓
THM-SHR-SRV
```

Now you can correlate:

```text
SOURCE                              DESTINATION
THM-MKT-WS                          THM-SHR-SRV
     │                                   │
     │ 4648                              │ 4624
     │                                   │
     └────────── credentials ───────────►│
```

🔥 **Much stronger evidence than looking at only one machine.**

---

# 12. 🟣 Sysmon Event 1

Sysmon Event 1 = **Process Creation**

Useful for identifying the command/process that initiated the connection.

Potentially useful fields:

```text
_time
User
Image
CommandLine
ParentImage
host
```

### Correlation

```text
4648
+
Sysmon 1
=
Source-side context
```

---

# 13. ⚠️ Credential Exposure Warning

Be careful with command-line logging.

Some commands can place sensitive credentials directly into command-line arguments.

For example, administrative tools may include:

```text
/user:<account>
```

and potentially credential material.

### SOC lesson

> **Command-line logging is valuable for detection, but it can also create sensitive-data exposure in logs.**

Logs themselves must therefore be protected.

---

# 14. 🚨 What Event 4648 Does NOT Detect

4648 requires **explicitly supplied credentials**.

It can occur with:

```text
net use /user:
runas
RDP credential prompt
```

But it does **not necessarily occur** with techniques that reuse existing authentication material.

Examples:

```text
Pass-the-Hash
Pass-the-Ticket
Single Sign-On
```

### Memory trick

```text
EXPLICIT credentials
        ↓
      4648

REUSED authentication material
        ↓
Don't depend on 4648
```

---

# 15. 🧠 Normal vs Suspicious

This is one of the **most important SOC concepts**.

The same Windows event can represent:

```text
LEGITIMATE ADMINISTRATION
        OR
MALICIOUS LATERAL MOVEMENT
```

The event itself isn't enough.

> **Context is everything.**

---

# 16. 🔎 Context Checklist

When investigating lateral movement, ask:

### 👤 WHO?

```text
Which account?
```

### 🖥️ FROM WHERE?

```text
Which source machine?
```

### 🎯 TO WHERE?

```text
Which destination?
```

### 🕐 WHEN?

```text
Business hours?
2 AM?
Weekend?
```

### 🔐 WHICH CREDENTIALS?

```text
Own credentials?
Alternate credentials?
Privileged account?
```

### 📈 WHAT PATTERN?

```text
One server?
10 servers?
50 servers?
```

### ⚙️ WHAT PROCESS?

```text
Normal admin tool?
cmd.exe?
powershell.exe?
Suspicious executable?
```

---

# 17. 🟢 Likely Legitimate

```text
IT Admin workstation
       ↓
IT admin account
       ↓
Business hours
       ↓
Known server
       ↓
Normal administrative task
       ↓
Single/small number of connections
```

---

# 18. 🔴 Worth Investigating

```text
Marketing workstation
       ↓
Non-admin user
       ↓
2 AM Saturday
       ↓
Privileged account
       ↓
Multiple workstations
       ↓
Rapid authentication attempts
       ↓
Administrative shares
```

That's a **very different story**.

---

# 19. 🧨 Typical Lateral Movement Pattern

```text
Initial compromise
       ↓
Discovery
       ↓
Find admin account
       ↓
Obtain/reuse credentials
       ↓
Source: Event 4648
       ↓
Remote authentication
       ↓
Destination: Event 4624
       ↓
Logon Type 3 / 10 / 7
       ↓
Remote execution/access
       ↓
5140 / process creation
       ↓
Lateral movement
```

---

# 20. 🛡️ Why Lateral Movement Works

Common security weaknesses:

### 🔴 Password Reuse

Same local administrator password across multiple machines.

```text
Compromise PC-01
      ↓
Steal local admin credential
      ↓
Same password on PC-02
      ↓
Access PC-02
      ↓
Repeat
```

### 🟢 Defense

**Microsoft LAPS** helps provide unique local administrator passwords per device.

---

### 🔴 Shared Administrative Accounts

Example:

```text
Administrator
      ↓
Used by many machines/admins
```

Makes attribution and containment harder.

---

### 🔴 Excessive Group Membership

Users receive more privileges than required.

```text
Normal user
    ↓
Unnecessary admin privileges
    ↓
Compromise
    ↓
Lateral movement
```

---

### 🔴 Poor Network Segmentation

If every workstation can communicate freely:

```text
PC-01 ─── PC-02 ─── PC-03
  │        │         │
  └────────┴─────────┘
```

Attackers get more opportunities to move.

---

### 🔴 Unnecessary RDP

RDP enabled everywhere increases the attack surface.

---

# 🧠 FINAL MEMORY MAP

```text
              LATERAL MOVEMENT
                     │
          ┌──────────┴──────────┐
          │                     │
       SOURCE              DESTINATION
          │                     │
      Event 4648             Event 4624
      Sysmon 1               Event 5140
          │                     │
          │                     │
     Who initiated?        Who connected?
     What credentials?     How did they logon?
     What target?          What did they access?
          │                     │
          └──────────┬──────────┘
                     ↓
                 CORRELATE
                     ↓
                  CONTEXT
                     ↓
          LEGITIMATE or MALICIOUS?
```

## 🔥 Must-Memorize SOC Table

|Artifact|Remember|
|---|---|
|**4624**|Successful logon|
|**4648**|Explicit credentials|
|**5140**|Network share accessed|
|**Sysmon 1**|Process creation|
|**Type 3**|Network / SMB / PsExec|
|**Type 7**|Unlock / RDP reconnect|
|**Type 10**|RDP|
|**4648 location**|Source|
|**4624 location**|Destination|
|**Context**|Determines suspiciousness|

### 🎯 Interview answer

> **When investigating lateral movement, I would correlate source and destination artifacts. Event 4648 helps identify explicit credential use on the source, while Event 4624 on the destination shows successful authentication and its logon type. I would then examine Event 5140, Sysmon process creation, source IP, user, target, timing and behavioral context. I wouldn't classify lateral movement from a single event because legitimate administrative activity can generate the same logs.**