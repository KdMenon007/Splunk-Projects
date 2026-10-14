
---

# 🌐 Logs Everywhere → Why SIEM Exists

## 1) Two Big Buckets of Log Sources

**Host-centric (on the box):**

- File access
    
- Auth attempts (success/fail)
    
- Process execution
    
- Registry add/edit/delete (Windows)
    
- PowerShell/CLI activity
    

**Network-centric (between boxes / to Internet):**

- SSH sessions
    
- FTP/SFTP file access
    
- Web traffic (HTTP/S)
    
- VPN logins and sessions
    
- SMB/NFS file-share activity
    

> Together, they generate massive, scattered, differently formatted event streams.

## 2) The Pain Points (a.k.a. why “grep over SSH” won’t cut it)

- **Too many sources** (hundreds/thousands; events per second).
    
- **No centralization** (RDP/SSH hopping = slow).
    
- **Limited context** (one log ≠ the story).
    
- **Human limits** (volume overwhelms manual review).
    
- **Format chaos** (Windows ≠ Linux ≠ Firewall ≠ Proxy).
    

---

# 🧠 SIEM: What It Does (and why you want it)

**Security Information and Event Management (SIEM)** collects, normalizes, correlates, and alerts — so you can see and act on _patterns_.

![[Pasted image 20251106064934.png]]

## Core Features

1. **Centralized Log Collection**
    
    - Agents/forwarders, APIs → one place to search.
        
2. **Parsing & Normalization**
    
    - Break raw logs into fields; convert to a **consistent schema**.
        
3. **Correlation**
    
    - Tie events across sources/time/users/hosts to reveal attack chains.
        
    - Example pattern in 5 minutes:
        
        - New/rare VPN IP → shared drive access → PowerShell exec → outbound connection → **possible exfil**
            
4. **Real-time Alerting**
    
    - Built-in + custom rules fire alerts; analysts get notified immediately.
        
5. **Dashboards & Reporting**
    
    - Actionable optics: alert highlights, system health, failed logins, ingest volume, top domains, rule hits.
        

> Extras you should know exist: threat intel integrations, long-term retention, fast query language, and scheduled reports.

---

# 🧾 Common Log Sources (What you actually ingest)

## Windows (Event Viewer)

- **Event IDs** make life sane.
    
- Forward to SIEM for centralized search and correlation.
    

## Linux

- **/var/log/httpd** or **/var/log/apache2**: Web access/error
    
- **/var/log/cron**: Scheduled jobs
    
- **/var/log/auth.log** or **/var/log/secure**: Auth events
    
- **/var/log/kern**: Kernel events
    
- Sample cron lines (noise + signal for job runs/failures).
    

## Web Servers (Apache example)

- Access logs show client IP, time, method, path, status, UA.
    
- Critical for web attack detection and lateral movement trails.
    

---

# 📥 Log Ingestion Methods (How it gets into SIEM)

- **Agent/Forwarder** (e.g., Splunk Universal Forwarder): tail files, send securely.
    
- **Syslog**: ubiquitous transport for network gear/unix daemons.
    
- **Manual Upload**: offline files for ad-hoc analysis (PCAPs, CSV, archived logs).
    
- **Listener/Port-forward**: SIEM listens on a port; sources forward events.
    

> Once ingested → parsed → normalized → searchable & correlatable.

---

# ⚡ Behind Triggered Alerts (Rules 101)

SIEM rules are **logical conditions** on parsed fields + time windows.

**Examples:**

- **5 failed logins in 10s** → “Multiple Failed Login Attempts”
    
- **Success after failures** → “Successful Login After Multiple Failures”
    
- **USB insert event** (if policy forbids) → alert
    
- **Outbound data > 25 MB** in short window → potential exfil (tune to policy/baselines)
    

## Building Rules (Windows examples)

**Use-case 1: Event Log Clearing**

- Signal: Windows **Event ID 104**
    
- Rule: `source=WinEventLog AND EventID=104` → **Alert: Event Log Cleared**
    

**Use-case 2: Post-exploit Recon (whoami)**

- Signal: **Event ID 4688** (process creation) + `NewProcessName` contains `whoami`
    
- Rule: `source=WinEventLog AND EventCode=4688 AND NewProcessName=*whoami*`  
    → **Alert: WHOAMI Command Execution Detected**
    

> Why normalization matters: rules trigger on **field:value** pairs reliably across sources.

---

# 🧪 Alert Investigation (What analysts actually do)

1. **See it on a dashboard** (priorities, spikes, health, notable events).
    
2. **Open the alert** → read fields, evidence, matched rule conditions.
    
3. **Pull related events/flows** (adjacent timestamps, same user/host/IP).
    
4. **Decide verdict**:
    
    - **False Positive** → document why; **tune** the rule (reduce noise).
        
    - **True Positive** → pivot deeper (user/asset/network context), check EDR, AD, VPN, proxy, mail.
        
5. **Act** (depending on authority/integrations):
    
    - Contact asset owner / user validation
        
    - Isolate host (via EDR/SOAR)
        
    - Block IP/domain/file hash
        
    - Escalate to L2/IR with findings and timeline
        

---

# 🗺 How it all ties together (mental model)

- **Logs everywhere** → SIEM **ingests**.
    
- SIEM **parses & normalizes** → fields become comparable.
    
- SIEM **correlates** → sequence/pattern emerges.
    
- **Rules fire** → alerts land with **context**.
    
- Analysts **investigate** → verdict → **response** (often via EDR/SOAR).
    
- **Tuning/feedback** → fewer FPs, better MTTD/MTTA/MTTR.
    

---

# ✅ Practical Cheat Sheet (copy/paste into your runbook)

**Host-centric:** process, auth, registry, file ops, PowerShell  
**Network-centric:** VPN, web, SSH, SMB/NFS, FTP

**Ingestion:** Agent / Syslog / Manual upload / Listener port  
**SIEM superpowers:** Centralize → Normalize → Correlate → Alert → Dashboard

**Windows rules you should memorize:**

- 4624/4625 (logon success/fail), 4688 (proc create), 104 (log cleared),
    
- 1102 (audit logs cleared), 4720/4728 (user/group changes), 7045 (service install)
    

**Typical correlations to hunt:**

- New geo/IP VPN login → Admin share access → PowerShell → outbound spike
    
- Service install (7045) → unusual parent process → network beacon
    
- Multiple local admin logons → lateral SMB connections → scheduled task creation
    

**After verdict:**

- FP → tune and document.
    
- TP → contain (EDR isolate/terminate/quarantine), block (FW/Proxy), notify, escalate with a timeline.
    

---

