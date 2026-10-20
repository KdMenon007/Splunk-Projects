
## 1. 🎯 PsExec in One Sentence

> **PsExec combines SMB + ADMIN$ + Windows Service Creation to execute commands remotely.**

This is the key difference:

```text
SMB Admin Share
      ↓
Copy files / access directories
      ↓
❌ Doesn't inherently execute remotely

PsExec
      ↓
SMB / ADMIN$
      ↓
Copy service binary
      ↓
Create Windows service
      ↓
Execute command remotely
      ↓
✅ Remote Code Execution
```

---

# 2. 🧠 How PsExec Works

Memorize this sequence:

```text
1. SMB connection
       ↓
2. ADMIN$ access
       ↓
3. Copy PSEXESVC.exe
       ↓
4. Create service
       ↓
5. Event 7045
       ↓
6. Named pipes
       ↓
7. Event 17
       ↓
8. Execute remote command
       ↓
9. Service cleanup
```

### The BIG detection clue

> **Event 7045 = New Windows Service Installed**

This is the primary artifact that separates **PsExec-style execution** from simple SMB file/share access.

---

# 3. 🔥 PsExec Artifacts

|Artifact|Event|Location|Why important|
|---|--:|---|---|
|Successful authentication|**4624**|Destination|Who authenticated|
|Admin share access|**5140**|Destination|ADMIN$/C$ access|
|Detailed share access|**5145**|Destination|Files/objects accessed|
|Service creation|**7045**|Destination|⭐ PsExec signature|
|Process creation|**Sysmon 1**|Both/source & destination|Commands/processes|
|Named pipe|**Sysmon 17**|Destination|PsExec communication|
|Explicit credentials|**4648**|Source|Credential usage|

### Memorize:

```text
4624 → LOGIN
5140 → SHARE
5145 → DETAILED SHARE
7045 → SERVICE
17   → PIPE
1    → PROCESS
4648 → EXPLICIT CREDS
```

---

# 4. 🚨 Event 7045 — THE BIG ONE

Event 7045:

> **A new service was installed.**

Default PsExec:

```text
Service Name:
PSEXESVC
```

Typical binary:

```text
C:\Windows\PSEXESVC.exe
```

### Important fields

```text
Service_Name
Service_File_Name
Service_Type
Service_Start_Type
Service_Account
```

---

# 5. 🔎 Splunk — Find New Services

```spl
index=win EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| sort _time
```

### Look for:

```text
Service_Name
      ↓
PSEXESVC

Service_File_Name
      ↓
C:\Windows\PSEXESVC.exe
```

But don't stop there.

Attackers can rename PsExec or use other implementations.

---

# 6. ⚠️ Default PsExec vs Renamed PsExec

### Default

```text
PSEXESVC
```

### Renamed

```text
renamed_psexec
```

### Other tools

Impacket's `psexec.py` and other frameworks may create **random service names**.

Therefore:

> ❌ Don't build your entire detection around `PSEXESVC`.

Instead hunt for **behavior**.

---

# 7. 🧠 Behavioral Detection

Look for:

```text
NEW SERVICE
+
USER MODE SERVICE
+
DEMAND START
+
REMOTE ADMIN/SMB ACTIVITY
```

Typical signature:

```text
Service_Type
    ↓
User mode service

Service_Start_Type
    ↓
Demand start
```

### Why this matters

Even if:

```text
PSEXESVC
```

becomes:

```text
WindowsUpdateHelper
```

the underlying service creation behavior still occurs.

---

# 8. 👑 PsExec `-s`

By default, PsExec executes the remote command under the authenticating user's context.

With:

```text
-s
```

the service runs as:

```text
LocalSystem
```

That's extremely powerful.

### Remember

```text
PsExec
   ↓
Remote execution

PsExec -s
   ↓
Remote execution as SYSTEM
```

---

# 9. 🔎 Find Commands Executed Through PsExec

Once you identify the destination host:

```spl
index=win EventCode=1 host={DESTINATION_HOST} ParentImage="*PSEXESVC*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

### Why `ParentImage` matters

You want:

```text
PSEXESVC.exe
       ↓
cmd.exe
       ↓
whoami / ipconfig / powershell / ...
```

So:

```text
ParentImage = PSEXESVC
```

can identify commands executed through the PsExec service.

---

# 10. 🧪 Sysmon Event 17 — Named Pipes

PsExec uses named pipes for:

```text
stdin
stdout
stderr
```

Sysmon:

```text
Event ID 17
```

= **Pipe Created**

### Hunt

```spl
index=win EventCode=17 Image="*PSEXESVC*"
| table _time, host, Image, PipeName
| sort _time
```

Possible pipe naming pattern:

```text
\PSEXESVC-<hostname>-<pid>-stdin
\PSEXESVC-<hostname>-<pid>-stdout
\PSEXESVC-<hostname>-<pid>-stderr
```

### 🔥 Important

Even if the executable gets renamed:

```text
evilservice.exe
```

the pipe naming convention may still expose PsExec-like behavior.

---

# 11. 🔍 Event 5145 — Detailed Share Access

Event 5140 tells you:

> A share was accessed.

Event 5145 gives you more detail about:

> **What specific object was accessed through the share.**

Important field:

```text
Relative_Target_Name
```

### Hunt

```spl
index=win EventCode=5145 host={DESTINATION_HOST} Relative_Target_Name="*PSEXE*"
| table _time, user, Source_Address, Share_Name, Relative_Target_Name
| sort _time
```

This can expose:

```text
Source_Address
User
Share_Name
Relative_Target_Name
```

---

# 12. 🧭 Finding the Source Host

One of the coolest investigation clues:

The named pipe can contain the **source hostname**.

Conceptually:

```text
\PSEXESVC-THM-MKT-WS-1234-stdin
```

You can potentially infer:

```text
Source = THM-MKT-WS
```

So the investigation becomes:

```text
DESTINATION
    ↓
5145
    ↓
Pipe/object
    ↓
Source hostname
    ↓
Pivot to source
```

---

# 13. 🖥️ Source-Side Detection

On the source host, Sysmon Event 1 can show the PsExec process itself.

```spl
index=win EventCode=1 host={SOURCE_HOST}
| search Image="*PsExec*"
| table _time, host, User, Image, CommandLine
| sort _time
```

### CommandLine can reveal:

```text
PsExec.exe \\TARGET cmd.exe
```

So you can determine:

```text
WHO?
   ↓
User

WHERE?
   ↓
Source host

TARGET?
   ↓
Remote server

WHAT?
   ↓
Remote command
```

---

# 14. 🔗 Full PsExec Investigation

This is the workflow to memorize.

```text
             SUSPICIOUS SMB
                    ↓
              ADMIN$ access
                    ↓
               Event 5140
                    ↓
            Destination host
                    ↓
              Event 7045
                    ↓
          New service created
                    ↓
       PSEXESVC / suspicious service
                    ↓
             Sysmon Event 1
                    ↓
         ParentImage = service
                    ↓
          Remote command executed
                    ↓
             Sysmon Event 17
                    ↓
              Named pipes
                    ↓
              Event 5145
                    ↓
           Source information
                    ↓
        Pivot to source machine
                    ↓
             Sysmon Event 1
                    ↓
             PsExec command
                    ↓
               CORRELATE
```

---

# 15. 🧠 Source vs Destination

|Question|Source|Destination|
|---|:-:|:-:|
|Who initiated?|✅|❌|
|PsExec.exe launched?|✅|❌|
|Target specified?|✅|❌|
|Authentication|—|✅ 4624|
|ADMIN$ access|—|✅ 5140|
|Service created|❌|✅ 7045|
|Remote command|—|✅ Sysmon 1|
|Named pipe|—|✅ Sysmon 17|
|Detailed share access|—|✅ 5145|

### Golden rule

> **PsExec's most distinctive artifacts are on the destination.**

---

# 16. ⚠️ 5140 / 5145 Audit Caveat

If you don't see:

```text
5140
5145
```

don't immediately conclude:

> "No SMB activity happened."

These events require appropriate auditing configuration.

Specifically:

```text
Audit File Share
Audit Detailed File Share
```

must be enabled.

So:

```text
No 5145
    ≠
No SMB
```

It could simply mean:

```text
Auditing wasn't enabled.
```

---

# 17. 🚨 Strong PsExec Detection Pattern

A very suspicious chain:

```text
Workstation
    ↓
SMB → ADMIN$
    ↓
4624
    ↓
5140
    ↓
7045 NEW SERVICE
    ↓
Suspicious service binary
    ↓
Sysmon 1
    ↓
Service spawns cmd/powershell
    ↓
Sysmon 17
    ↓
Named pipes
```

🔥 **Multiple correlated artifacts = much higher confidence.**

---

# 18. 🆚 SMB vs PsExec

| Feature | Plain SMB | PsExec |
|---|---|---|
| SMB | ✅ | ✅ |
| ADMIN$ | Possible | ✅ |
| Copy files | ✅ | ✅ |
| Browse directories | ✅ | ✅ |
| Remote command execution | ❌ | ✅ |
| Service creation | ❌ | ✅ |
| Event 7045 | ❌ normally | ⭐ |
| Named pipes | Possible | ⭐ Characteristic |
| Sysmon 1 | Depends | Useful |
| Event 5145 | Possible | Useful |

### The key distinction:

```text
SMB
 ↓
ACCESS

PsExec
 ↓
ACCESS
 ↓
SERVICE
 ↓
EXECUTE
```

---

# 19. 🎯 Interview Answer

> **PsExec is a lateral-movement technique that combines SMB administrative-share access with Windows service creation to execute commands remotely. On the destination, I'd look for Event 7045 as the primary service-creation artifact, then correlate Sysmon Event 1 for processes spawned by PSEXESVC and Sysmon Event 17 for named pipes. Event 5145 can provide detailed share activity and potentially source-host information. On the source, Sysmon Event 1 can show the PsExec command and target. I would correlate these artifacts rather than relying solely on the PSEXESVC filename because attackers can rename the service or use alternative PsExec implementations.**

---

# 🧠 15-Second SOC Memory Card

```text
PsExec = SMB + ADMIN$ + SERVICE + EXECUTION

7045 → NEW SERVICE ⭐
5140 → ADMIN$ / SHARE
5145 → DETAILED SHARE
4624 → AUTHENTICATION
4648 → EXPLICIT CREDS
Sysmon 1 → PROCESS
Sysmon 17 → NAMED PIPE

PSEXESVC → DEFAULT NAME
-s → SYSTEM

DON'T HUNT ONLY:
"PSEXESVC"

HUNT:
NEW SERVICE
+
DEMAND START
+
USER-MODE SERVICE
+
SMB/ADMIN$
+
REMOTE PROCESS EXECUTION
```

### 🔥 The one thing to tattoo into your SOC brain:

> **Plain SMB gives remote access. PsExec adds service creation to turn that access into remote execution.**