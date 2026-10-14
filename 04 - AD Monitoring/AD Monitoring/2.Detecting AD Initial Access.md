# 🌐 AD Attack Surface — IIS, Exchange & VPN 
## 1. Why AD Changes the Attack Surface

```text
Standalone Server
        ↓
Compromise Server
        ↓
Impact mostly limited to that host


AD-Connected Service
        ↓
Web / Exchange / VPN
        ↓
AD Authentication
        ↓
Compromised AD Account
        ↓
Potential Domain-Wide Access
```

### 🧠 Core idea

> **An AD-connected application is not just an application attack surface — it can become an identity attack surface.**

Common AD-connected entry points:

- IIS web applications
    
- Exchange / OWA
    
- VPN gateways
    
- Internal applications
    
- Remote access services
    

---

# 2. IIS — Internet Information Services

**IIS = Microsoft's Windows web server platform.**

Common applications hosted on IIS:

- Exchange
    
- SharePoint
    
- ASP.NET applications
    
- Internal business applications
    

### Authentication flow

```text
User
 ↓
IIS Application
 ↓
Active Directory
 ↓
Authentication Result
```

Possible logs:

```text
IIS
 ↓
IIS Access Logs

Windows Web Server
 ↓
4624 / 4625

Domain Controller
 ↓
4776
```

---

# 3. IIS Log Location

Default:

```text
C:\inetpub\logs\LogFiles\W3SVC1
```

### ⚠️ Timezone

> **IIS timestamps are UTC.**

Windows Security events generally use the machine's configured local time.

When correlating:

```text
IIS UTC
   ↓
Convert / normalize time
   ↓
Windows Security timestamp
```

---

# 4. Important IIS Fields

|Field|Meaning|SOC Use|
|---|---|---|
|`c-ip`|Client IP|Source/attacker IP|
|`cs-uri-stem`|Requested URI|Identify targeted resource|
|`cs-uri-query`|Query string|Commands / parameters|
|`cs-method`|HTTP method|GET / POST|
|`sc-status`|HTTP status|Success/failure/redirect|
|`cs(User-Agent)`|Client identifier|Tool/browser clues|

---

# 5. IIS HTTP Status Codes

|Status|Meaning|SOC Context|
|--:|---|---|
|`200`|Success|Request succeeded|
|`302`|Redirect|Common with OWA|
|`401`|Unauthorized|Authentication failure/requirement|
|`404`|Not Found|Scanning / nonexistent resource|

### 🚨 Important

```text
Hundreds of 404s
+
Same source IP
+
Short timeframe
```

→ Possible **directory scanning**

---

# 6. Normal vs Suspicious IIS

|Category|Normal|Suspicious|
|---|---|---|
|Login volume|Few attempts|Hundreds/minutes|
|Time|Business hours|03:00 AM|
|Source|Known subnet|Unknown IP/subnet|
|URI|`/owa/`, `/ecp/`|Unexpected `.aspx`|
|Query|Normal parameters|`cmd=whoami`|
|POST|Login forms|POST to shell-like path|
|404s|Occasional|Hundreds from one IP|

---

# 7. Web Shell

A **web shell** is malicious server-side code that gives an attacker command execution through HTTP requests.

Typical IIS web shell:

```text
.aspx
```

Attack flow:

```text
Internet
   ↓
Exploit IIS Application
   ↓
Upload Web Shell
   ↓
HTTP Request
   ↓
w3wp.exe
   ↓
cmd.exe / powershell.exe
   ↓
OS Command Execution
```

### 🚨 Core detection

```text
w3wp.exe
   ↓
cmd.exe
```

or:

```text
w3wp.exe
   ↓
powershell.exe
```

This is highly suspicious because IIS worker processes normally shouldn't need to launch command shells.

---

# 8. Web Shell Detection — Process Chain

### Normal

```text
w3wp.exe
   ↓
Application processing
```

### Suspicious

```text
w3wp.exe
   ↓
cmd.exe
   ↓
whoami
ipconfig
```

or:

```text
w3wp.exe
   ↓
powershell.exe
```

### 🧠 SOC rule

> **Parent process matters.**

Don't simply ask:

```text
"Did cmd.exe run?"
```

Ask:

```text
"Who spawned cmd.exe?"
```

---

# 9. Web Shell Investigation — Step 1

Find scanning activity:

```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

### Goal

Find:

```text
Suspicious IP
+
High 404 count
```

---

# 10. Web Shell Investigation — Step 2

Find successful requests from suspicious IP:

```spl
index=iis c_ip={SUSPICIOUS_IP} sc_status=200
| stats count by cs_uri_stem
| sort - count
```

### Look for

```text
.aspx
shell.aspx
cmd.aspx
Unexpected application paths
```

---

# 11. Web Shell Investigation — Step 3

Filter suspicious shell:

```spl
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

### Important field

```text
cs_uri_query
```

Potential indicators:

```text
cmd=whoami
exec=ipconfig
cmd=hostname
```

---

# 12. Web Shell → Process Correlation

```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

### Look for

```text
w3wp.exe
 ↓
cmd.exe
 ↓
whoami

w3wp.exe
 ↓
powershell.exe

w3wp.exe
 ↓
net.exe
```

---

# 13. Web Shell Deployment — Sysmon 11

```spl
index=win EventCode=11 TargetFilename="*{WEBSHELL_FILENAME}"
| table _time, Image, TargetFilename
```

### Event

```text
Sysmon 11
→ FileCreate
```

Useful for identifying:

> **When the web shell was written to disk.**

---

# 14. Web Shell Alternative Detection

If Sysmon Event 11 isn't available:

```spl
index=iis cs_method=POST cs_uri_query="*{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
| sort _time
```

---

# 15. Important Web Shell Location

A commonly abused IIS location:

```text
/aspnet_client/
```

Why interesting?

- Default IIS/ASP.NET directory.
    
- Writable in some configurations.
    
- Normally contains client-side ASP.NET resources.
    
- Unexpected application code there deserves investigation.
    

### 🚨 Don't blindly whitelist by filename.

Check:

```text
Path
+
File creation event
+
Parent process
+
HTTP request
+
Command execution
```

---

# 16. Web Shell Investigation Chain

```text
404 Burst
   ↓
Identify Source IP
   ↓
200 Requests
   ↓
Find Suspicious .aspx
   ↓
Inspect cs_uri_query
   ↓
Find w3wp.exe Child Processes
   ↓
Check Sysmon 11
   ↓
Determine Deployment Time
   ↓
Scope Post-Exploitation
```

---

# 17. Exchange / OWA

### Exchange

Email, calendar and contacts platform.

### Outlook

Desktop email client.

### OWA

**Outlook Web Access**

Browser-based Exchange interface running on IIS.

```text
Internet
   ↓
IIS
   ↓
OWA
   ↓
Active Directory
```

---

# 18. Important Exchange Paths

|Path|Purpose|SOC Importance|
|---|---|---|
|`/owa`|Outlook Web Access|Credential attacks|
|`/ecp`|Exchange Control Panel|Administrative access|
|`/powershell`|Exchange PowerShell|Highly sensitive|

### 🧠 Remember

```text
/owa
→ Login

/ecp
→ Admin

/powershell
→ Administrative command interface
```

---

# 19. Normal OWA Login

Typical pattern:

```text
POST /owa/auth.owa
       ↓
302 redirect
       ↓
GET inbox/resources
```

### Important

A successful and failed OWA login can both generate:

```text
302
```

Therefore:

> **HTTP 302 alone does NOT prove successful authentication.**

---

# 20. OWA Failed Login

OWA can use:

```text
reason=2
```

to indicate a failed login.

But for reliable username information:

```text
IIS Logs
     +
Windows Security Logs
```

---

# 21. OWA Brute Force

### Detection pattern

```text
POST /owa/auth.owa
+
Same source IP
+
High volume
+
Short timeframe
```

### Splunk

```spl
index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
| bin _time span=5m
| stats count by _time, c_ip
| where count > 10
| sort - count
```

---

# 22. Brute Force vs Password Spraying

At the IIS level:

```text
Many POSTs
+
Same IP
```

could be:

### Brute Force

```text
One account
+
Many passwords
```

### Password Spraying

```text
Many accounts
+
Small number of passwords
```

IIS may not reveal the targeted username clearly.

Therefore pivot to:

```text
Windows Event 4625
```

---

# 23. Identify Target Account

```spl
index=win EventCode=4625
| stats count by user, Logon_Type
| sort - count
```

### Interpretation

```text
One user
+
Huge failure count
```

→ Brute force more likely.

```text
Many users
+
Failures distributed across accounts
```

→ Password spraying more likely.

---

# 24. OWA Authentication Correlation

```spl
index=win EventCode IN (4624, 4625) user="{TARGETED_USER}" Logon_Type=8
| table _time, EventCode, user, Process_Name, Logon_Type
| sort _time
```

### Pattern

```text
4625
4625
4625
4625
   ↓
4624
```

→ Possible successful credential attack.

### Logon Type 8

```text
8
→ NetworkCleartext
```

Commonly seen with IIS-hosted application authentication.

---

# 25. Critical OWA Investigation Limitation

The real attacker IP may **not** appear in Windows Security 4624/4625.

You may see:

```text
IIS
→ Real attacker IP
```

while:

```text
Windows Security
→ Local / empty source address
```

Therefore:

> **Use IIS to identify the source IP; use Windows Security logs to identify the account and authentication result.**

---

# 26. Post-Authentication Exchange Investigation

Once attacker IP is identified:

```spl
index=iis c_ip="{ATTACKER_IP}"
| stats count by cs_uri_stem
| sort - count
```

### Look for

```text
/owa
/ecp
/powershell
```

Especially:

```text
Successful OWA login
        ↓
/ecp
        ↓
/powershell
```

→ Escalating beyond normal email access.

---

# 27. VPN Attack Surface

VPN is another AD-connected entry point.

```text
Internet
   ↓
VPN Gateway
   ↓
RADIUS / NPS
   ↓
Active Directory
```

Common VPN products:

- Fortinet
    
- Cisco
    
- Palo Alto
    
- Ivanti
    

---

# 28. RADIUS / NPS

**RADIUS** is commonly used between the VPN gateway and authentication server.

On Windows:

```text
NPS
=
Network Policy Server
```

### Flow

```text
VPN Client
   ↓
VPN Gateway
   ↓
RADIUS
   ↓
NPS
   ↓
Active Directory
```

---

# 29. Important NPS Events

|Event|Meaning|Security Relevance|
|--:|---|---|
|**6272**|Access granted|Successful VPN authentication|
|**6273**|Access denied|Failed VPN authentication|
|**6274**|Request discarded|Malformed/rejected request|

---

# 30. NPS Reason Codes

|Reason Code|Meaning|Interpretation|
|--:|---|---|
|**16**|Unknown username / bad password|🚨 Credential attack indicator|
|**48**|No matching network policy|⚠️ Configuration / authorization|
|**65**|RADIUS shared secret mismatch|⚠️ Misconfiguration|

### 🧠 Memory

```text
16 → Bad credentials
48 → Policy
65 → Shared secret
```

---

# 31. VPN Brute Force Pattern

Normal:

```text
Occasional 6273
+
Expected location
+
Business hours
+
Known user
```

Suspicious:

```text
6273
6273
6273
6273
6273
...
+
Same username
+
Rapid succession
```

→ Possible brute force.

---

# 32. VPN Password Spraying

```text
Same source
+
Many usernames
+
Few attempts per username
```

→ Password spraying.

Compare:

```text
Brute Force
→ One account
→ Many passwords
```

```text
Password Spray
→ Many accounts
→ Few common passwords
```

---

# 33. VPN Investigation — Step 1

Find NPS failures:

```spl
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

### Important caveat

`Client_IP_Address` is generally the:

> **VPN gateway / RADIUS client**

not necessarily the user's real Internet IP.

---

# 34. VPN Investigation — Step 2

Check whether authentication eventually succeeded:

```spl
index=win EventCode IN (6273,6272) User_Account_Name={COMPROMISED_USER}
| table _time, EventCode, User_Account_Name, Client_IP_Address
```

### Suspicious pattern

```text
6273
6273
6273
6273
   ↓
6272
```

Possible credential attack followed by successful authentication.

---

# 35. VPN Investigation — Step 3

Correlate with Security logs:

```spl
index=win EventCode IN (4624, 4625) user={COMPROMISED_USER}
| table _time, host, user, EventCode, Logon_Type
| sort _time
```

### Why?

NPS tells you:

```text
VPN authentication result
```

Security logs tell you:

```text
Windows authentication/session
```

---

# 36. VPN Detection When There Are No Failures

This is important.

Attackers may already possess valid credentials.

Then:

```text
6272
```

may appear **without preceding 6273 events**.

That can look completely legitimate.

Therefore:

```text
Successful authentication
        ↓
Post-authentication behavior
        ↓
Resource access
        ↓
Lateral movement
        ↓
Anomalies
```

### 🧠 SOC lesson

> **A successful login is not proof of a legitimate user.**

---

# 37. IIS vs Exchange vs VPN

| Attack Surface | Main Log | Key Event / Signal | Primary Detection |
|---|---|---|---|
| IIS | IIS Access Logs | 404 / POST / Suspicious URI | Scanning + Web Shell |
| IIS Web Shell | Sysmon | Event 1 / 11 | `w3wp.exe` → `cmd.exe` / `powershell.exe` |
| OWA | IIS + Security | `POST /owa/auth.owa` + 4625/4624 | Brute Force / Password Spraying |
| Exchange Admin | IIS | `/ecp` / `/powershell` | Post-Authentication Escalation |
| VPN | NPS | 6272 / 6273 | Credential Attacks |
| VPN + AD | Security | 4624 / 4625 | Authentication / Session Activity |
| VPN + DC | Security | 4776 | Credential Validation |
```

---

# 🎯 38. Attack Investigation Flow

```text
                INTERNET
                   │
       ┌───────────┼───────────┐
       │           │           │
      IIS        Exchange      VPN
       │           │           │
       │          OWA         NPS
       │           │           │
       └───────────┼───────────┘
                   ↓
              AD ACCOUNT
                   ↓
          Authentication Logs
                   ↓
             4624 / 4625
                   ↓
          What happened next?
                   ↓
       ┌───────────┼───────────┐
       │           │           │
   Web Shell   Lateral Move   Privilege
       │           │           │
      EDR         SMB/RDP       AD Changes
```

---

# 🧠 39. SOC L1/L2 Investigation Questions

Whenever you see an authentication alert, ask:

```text
1. WHO?
   → Username

2. WHERE FROM?
   → Source IP / workstation

3. WHEN?
   → Timestamp

4. WHAT SERVICE?
   → IIS / OWA / VPN / SMB

5. SUCCESS OR FAILURE?
   → 4624 vs 4625
   → 6272 vs 6273

6. HOW MANY?
   → Volume

7. ONE ACCOUNT OR MANY?
   → Brute force vs spraying

8. IS THE SOURCE NORMAL?
   → Known subnet / VPN gateway / admin workstation

9. IS THE TIME NORMAL?
   → Business hours / maintenance window

10. WHAT HAPPENED AFTER SUCCESS?
    → ECP / PowerShell / SMB / RDP / suspicious processes
```

---

# 🔥 Final Memory Map

```text
IIS
│
├── c-ip → Source IP
├── cs-uri-stem → URI
├── cs-uri-query → Parameters/commands
├── cs-method → GET/POST
└── sc-status → HTTP result
      │
      └── 404 burst → Scanning
      └── .aspx → Possible Web Shell
      └── POST → Investigate
      └── w3wp → cmd → 🚨


EXCHANGE
│
├── /owa → Login
├── /owa/auth.owa → Authentication
├── /ecp → Admin
└── /powershell → High-risk admin interface
      │
      ├── 4625 → Failed login
      └── 4624 → Successful login


VPN
│
├── VPN Gateway
│      ↓
├── RADIUS
│      ↓
├── NPS
│      ├── 6272 → Success
│      ├── 6273 → Failure
│      └── 6274 → Discarded
│
└── AD
       └── 4776 → Credential validation
```

## 🏆 One-line SOC takeaway

> **Follow the identity across the logs: IIS tells you _where the request came from_, Windows Security tells you _which account authenticated_, and NPS/AD tells you _how the identity was validated_. Then investigate what that identity did after authentication.**