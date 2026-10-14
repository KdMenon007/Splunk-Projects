
You’re asking John (our imaginary SOC analyst) to solve four big, very real-world problems:

- Event breaking
    
- Multi-line event handling
    
- Sensitive data masking
    
- Custom field extraction
    

This is **props.conf + transforms.conf** territory — the heart of Splunk parsing.

Let me set the stage cleanly and get you ready for the lab.

---

# **Scenario: You Are John — SOC Analyst at CyberT**

A client is onboarding a **custom log source** into Splunk.  
Because the logs are not standard (not Windows, not Syslog, not IIS, etc.), Splunk can’t parse them correctly out of the box.

The issues you need to fix:

---

# **1. Event Breaking**

Splunk is treating multiple events as one, or breaking single events into multiple ones.

Example symptoms:

- One log entry becomes three
    
- Ten log entries merge into one giant monster
    
- Timestamp is not recognized
    
- No `_time` field extracted
    
- Log lines look “glued together”
    

**Fix:** Define event boundaries using `LINE_BREAKER`, `SHOULD_LINEMERGE`, or proper timestamp rules in `props.conf`.

---

# **2. Multi-line Events**

Custom logs often contain multi-line messages:

- Stack traces
    
- Error messages
    
- Application logs
    
- JSON blobs
    
- Long transaction dumps
    

If Splunk is not configured, it will split these into “partial events,” making the logs unreadable.

**Fix:** Use:

```
SHOULD_LINEMERGE = true
TRUNCATE = <larger size>
TIME_PREFIX = ...
```

And sometimes regex patterns to identify the _start_ of each event.

---

# **3. Masking Sensitive Data (PCI-DSS Requirement)**

The client deals with financial info.  
Logs contain sensitive fields like credit card numbers.

Because Splunk stores _raw_ data forever, PCI requires:

- Redaction
    
- Anonymization
    
- Tokenization
    

**Fix:** Use a `transforms.conf` rule with regex to **replace** sensitive fields before indexing.

Example:

```
REGEX = (\d{4}-?\d{4}-?\d{4}-?\d{4})
FORMAT = ****-****-****-****
DEST_KEY = _raw
```

This ensures logs **never** land in Splunk in an unmasked form.

---

# **4. Custom Field Extraction**

Some fields in the weblogs:

- are redundant
    
- are mis-extracted
    
- have dirty values
    
- need cleanup or removal
    

This requires updating the pipeline with:

- **FIELDALIAS**
    
- **EXTRACT-**
    
- **REPORT-**
    
- **KV_MODE modifications**
    
- or dropping unwanted keys using transforms.
    

Example:

```
EXTRACT-userIP = clientIP=(?\d+\.\d+\.\d+\.\d+)
```

---

# **Your Mission in the Lab**

You’ll learn to manipulate logs using Splunk’s configuration files:

### **props.conf**

Controls:

- event breaking
    
- line merging
    
- sourcetype behaviors
    
- timestamp extraction
    
- field extraction mappings
    

### **transforms.conf**

Controls:

- anonymization
    
- redaction
    
- event routing
    
- field removal
    
- regex-based extraction
    

These configurations affect Splunk at **index time** — meaning changes modify how raw data is interpreted _before_ it’s stored.

This is exactly how real-world Splunk engineers onboard new data sources.

---
# **Splunk Data Parsing — How It Actually Works**

Splunk’s power comes from its ability to take messy, unstructured logs and turn them into structured, searchable events. To make that happen, Splunk uses a parsing pipeline controlled by configuration files such as:

- inputs.conf
    
- props.conf
    
- transforms.conf
    
- indexes.conf
    
- outputs.conf
    
- authentication.conf
    

This section breaks down the parsing flow and the stanzas that control how Splunk interprets your data.

---

# **Step 1: Understand the Data Format**

Before you create any extraction or transformation rules, you need to understand:

- What do the events look like?
    
- Are they single-line or multi-line?
    
- Where is the timestamp?
    
- Are fields key-value, CSV, or buried in free text?
    
- Are there sensitive fields (PCI, PII)?
    
- Do events require custom breaking?
    

Splunk can ingest:

- JSON
    
- XML
    
- syslog
    
- Windows logs
    
- CSV
    
- Custom web logs
    
- Application logs
    

But if it’s a custom format, **you have to teach Splunk how to read it.**

---

# **Step 2: Assign (or Create) a Sourcetype**

A _sourcetype_ tells Splunk what the data "looks like."

If Splunk can’t identify the sourcetype, it won’t parse timestamps, fields, or event boundaries properly.

Example:

```
[source::/path/to/your/data]
sourcetype = custom_logs
```

Now any log coming from `/path/to/your/data` uses the sourcetype `custom_logs`.

---

# **Step 3: Configure `props.conf`**

`props.conf` is the **heart** of Splunk parsing.

It controls:

- timestamp extraction
    
- event breaking
    
- line merging
    
- field extraction rules
    
- whether transforms should run
    
- KV parsing
    
- masking rules (via transforms.conf references)
    

Basic stanza structure:

```
[custom_logs]
SHOULD_LINEMERGE = false
LINE_BREAKER = ...
TIME_PREFIX = ...
TIME_FORMAT = ...
REPORT-myfields = extract_fields
TRANSFORMS-mask = cc_masking
```

---

# **Step 4: Define Field Extractions**

You can extract fields in **two ways**:

### **1. EXTRACT-***

Quick extraction using regex directly in `props.conf`.

```
[custom_logs]
EXTRACT-user = user=(?<user>\w+)
```

### **2. REPORT-***

For more complex patterns stored in `transforms.conf`.

```
[custom_logs]
REPORT-fields = extract_custom_fields
```

Then in `transforms.conf`:

```
[extract_custom_fields]
REGEX = user=(?<user>\w+).*?action=(?<action>\w+)
```

---

# **Step 5: Restart Splunk**

Changes to parsing configs require a restart:

```
./splunk restart
```

This ensures Splunk re-parses incoming data with your updated rules.

---

# **Step 6: Validate in Search**

Use:

```
sourcetype=custom_logs
```

Check:

- Are events split correctly?
    
- Is the timestamp correct?
    
- Are custom fields extracted?
    
- Are sensitive fields masked?
    
- Do multi-line events look normal?
    

Once everything is working, you’re ready to ingest full production logs.

---

# **Core Splunk Config Files Explained**

Here’s a clean breakdown of the files you introduced.

---

## **inputs.conf — What Splunk Collects**

Defines **what** data is being ingested.

```
[monitor:///path/to/logfile.log]
sourcetype = my_sourcetype
index = custom_index
```

---

## **props.conf — How Splunk Parses It**

Controls event structure + extraction + parsing.

```
[my_sourcetype]
SHOULD_LINEMERGE = false
EXTRACT-field1 = regex_1
REPORT-field2 = transform_name
KV_MODE = json
```

---

## **transforms.conf — Transformations & Masking**

Used for:

- masking
    
- routing
    
- field renaming
    
- event dropping
    
- advanced extractions
    

```
[mask_sensitive]
REGEX = (\d{4}-\d{4}-\d{4}-\d{4})
FORMAT = ****-****-****-****
DEST_KEY = _raw
```

---

## **indexes.conf — Where the Data Lives**

Controls:

- index creation
    
- storage paths
    
- retention limits
    

```
[my_index]
homePath = $SPLUNK_DB/my_index/db
coldPath = $SPLUNK_DB/my_index/colddb
maxTotalDataSizeMB = 100000
```

---

## **outputs.conf — Where Data Gets Sent**

Used when this Splunk instance is forwarding data elsewhere.

```
[tcpout]
defaultGroup = main_indexer

[tcpout:main_indexer]
server = indexer.company.com:9997
```

---

## **authentication.conf — User Access Controls**

Configure auth mechanisms (LDAP, SAML, etc.)

```
[authentication]
authSettings = LDAP
```

---

# **Common Stanzas in props.conf (Master Reference)**

|**Stanza**|**Purpose**|**Example**|
|---|---|---|
|`[sourcetype]`|Defines parsing rules per sourcetype|`[apache:access]`|
|`TRANSFORMS-xxx`|Apply transform rules|`TRANSFORMS-mask = mask_sensitive`|
|`REPORT`|Map transform to sourcetype|`REPORT-fields = extract_fields`|
|`EXTRACT`|Inline field extraction|`EXTRACT-user = (?<user>\w+)`|
|`TIME_PREFIX`|Pattern before timestamp|`TIME_PREFIX = \[`|
|`TIME_FORMAT`|Timestamp syntax|`%Y-%m-%d %H:%M:%S`|
|`LINE_BREAKER`|Where to split events|`LINE_BREAKER = ([\r\n]+)`|
|`SHOULD_LINEMERGE`|Merge multi-line events|`SHOULD_LINEMERGE = true/false`|
|`BREAK_ONLY_BEFORE`|Event starts when regex matches|`^2023-\d\d-\d\d`|
|`BREAK_ONLY_AFTER`|Event ends with pattern|`\[END\]`|
|`KV_MODE`|Key-value field extraction|`KV_MODE = json`|

You’re now officially armed with the full Splunk parsing toolkit.

---

## 1. What you’ve actually built

You now have:

- **A custom Splunk app**: `DataApp` in `/opt/splunk/etc/apps/DataApp/`
    
- **Scripted inputs** defined in `inputs.conf`:
    
    - `samplelogs.py` → sends “This is a sample log…” every 5 seconds
        
    - `vpnlogs` → generates custom VPN logs every 5 seconds with `sourcetype=vpn_logs`
        
- **Custom parsing rules** in `props.conf` for `sourcetype=vpn_logs` to fix event breaking.
    

So you’ve gone from:  
“Random script prints text” → “Structured, searchable VPN events inside Splunk.”

That’s exactly what SIEM engineers do in real environments.

---

## 2. How Splunk is handling these VPN logs under the hood

### a) `inputs.conf` – _how data enters Splunk_

You told Splunk:

```ini
[script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]
index = main
source = vpn
sourcetype = vpn_logs
interval = 5
```

Meaning:

- Run this script **every 5 seconds**
    
- Treat its output as events
    
- Tag them with:
    
    - `index=main`
        
    - `source=vpn`
        
    - `sourcetype=vpn_logs` ← very important, this ties into props.conf
        

So all the parsing logic later is scoped to `sourcetype=vpn_logs`.

---

### b) Initial problem: event breaking

The sample logs:

```text
User: Emily Davis, Server: Server C, Action: DISCONNECT
User: John Doe, Server: Server B, Action: DISCONNECT
User: Bob Johnson, Server: Server B, Action: DISCONNECT
...
User: Michael Brown, Server: Server E, Action: CONNECT
```

What went wrong initially:

- Splunk didn’t recognize each line as a **separate event boundary** correctly.
    
- So multiple logical events were being crammed into a single Splunk event.
    

By default, Splunk tries to break events at line boundaries and uses its own heuristics. With custom/generated logs, those heuristics often suck.

---

## 3. Fixing event boundaries with `props.conf`

You created a `props.conf` in `DataApp/default/`:

```ini
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)
```

What this actually does:

- `SHOULD_LINEMERGE = true`
    
    - Tells Splunk: “Feel free to merge multiple lines into a single event _until_ you see my explicit break rule.”
        
- `MUST_BREAK_AFTER = (DISCONNECT|CONNECT)`
    
    - After a line that matches this regex, **force** a new event.
        
    - Since every log line ends with `Action: CONNECT` or `Action: DISCONNECT`, each line becomes its own event.
        

Result:  
Each VPN line = **1 clean Splunk event**, instead of one giant blob.

---

## 4. Alternative ways you could solve this (good for interviews)

If you want tighter control (or different multi-line logic), you could do for the same `sourcetype=vpn_logs`:

### Option A – simple 1 line = 1 event

```ini
[vpn_logs]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
```

- No merging, just split on newline.
    
- Good if logs are guaranteed 1-line-per-event.
    

### Option B – multi-line events that **start with “User:”**

If there were stack traces or extra lines attached:

```ini
[vpn_logs]
SHOULD_LINEMERGE = false
BREAK_ONLY_BEFORE = ^User:\s
```

- Only break when a line **starts** with `User:`
    
- Everything in between is part of the same event.
    

What you did with `MUST_BREAK_AFTER` is basically the inverse:  
Instead of “break before the header,” you said “break after the tail.”

---

## 5. Where this ties into the bigger picture (your earlier notes)

You’ve now used:

- **`inputs.conf`** – define _how data comes in_ (scripted input, file monitors, etc.)
    
- **`props.conf`** – control _how raw data becomes events_ (event breaking, timestamps, field extractions, etc.)
    
- Soon you’d combine with:
    
    - **`transforms.conf`** – masking CC numbers, rewriting fields, dropping noise
        
    - **`indexes.conf`** – what index this stuff lands in and retention
        
    - **`outputs.conf`** – if this box is a forwarder sending to another Splunk
        

And on top of that:

- You already know SPL search skills: `fields`, `table`, `top`, `rare`, `stats`, `timechart`, etc.
    
- You’ve touched **reports**, **dashboards**, and **alerts** conceptually.
    

So you’re now playing at both layers:

- **Analytics layer** – SPL, searches, dashboards, alerts
    
- **Data onboarding layer** – inputs, props, scripted logs, event breaking
    

That combo is exactly what makes a strong SOC / SIEM engineer.

---

## 6. If you want a quick next move

Here are some spicy next steps you can try in the same lab/app without changing much:

1. **Add field extraction for the VPN logs** in `props.conf`:
    

```ini
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)
EXTRACT-vpn_fields = User:\s(?<user>[^,]+),\sServer:\s(?<server>[^,]+),\sAction:\s(?<action>\w+)
```

Then in Splunk Search:

```spl
index=main sourcetype=vpn_logs
| stats count by user, server, action
```

2. **Simulate PCI DSS masking** with `transforms.conf` for, say, a fake `cc_number` field.
    
3. **Build a tiny dashboard** that shows:
    
    - VPN connections by user
        
    - VPN disconnects over time with `timechart`
        

---

## 1. Big Picture: How Splunk Actually Flows

**Data path:**

1. **Source**
    
    - OS logs (Linux `/var/log/syslog`, Windows Event Logs)
        
    - Web logs (IIS `C:\inetpub\logs\LogFiles\W3SVC*`)
        
    - Custom scripts (`vpnlogs`, `authentication_logs`, `purchase-details`, etc.)
        
2. **Forwarder**
    
    - **Universal Forwarder (UF)**:
        
        - Lightweight, no parsing/indexing, just ships data.
            
        - Used on endpoints: Linux servers, Windows hosts, web servers.
            
    - **Heavy Forwarder (HF)**:
        
        - Can parse, filter, transform _before_ forwarding.
            
        - Used when you want source-side pre-processing.
            
3. **Indexers / Splunk Enterprise**
    
    - You configured **listener on 9997**.
        
    - Data lands in a specific **index** (e.g. `Linux_host`, `main`, IIS index, Windows index).
        
4. **Search Head / Search & Reporting App**
    
    - Analysts use **SPL**, reports, dashboards, alerts.
        

That’s the end-to-end story.

---

## 2. Core UI & SPL Concepts

### Search & Reporting App pieces

- **Search Head** – where you type SPL.
    
- **Time picker** – never blindly use `All time` in prod. SOC suicide.
    
- **Search History** – reused queries, filter old searches.
    
- **Data Summary** – quick view of indexes, sources, hosts.
    
- **Field Sidebar**
    
    - _Selected fields_: default (`host`, `source`, `sourcetype`, etc.) + what you pin.
        
    - _Interesting fields_: fields Splunk thinks are useful.
        
    - `α` = text fields, `#` = numeric fields.
        
    - _Count_ = how many events contain that field.
        

---

### SPL Basics – Operators & Filters

#### Comparison operators

Examples:

```spl
index=windowslogs AccountName!=SYSTEM
index=windowslogs Age < 10
Outbound_traffic >= 50
```

#### Boolean operators

```spl
index=windowslogs AccountName!=SYSTEM AND AccountName=James
field_A=value1 OR field_A=value2
field_A NOT value
```

#### Wildcards

```spl
index=windowslogs DestinationIp=172.*
status=fail*
```

---

### Filter / Projection Commands

**`fields`** – show/hide fields

```spl
index=windowslogs | fields + host + User + SourceIp
index=windowslogs | fields + HostName - EventID
```

**`search`** – search in the pipeline

```spl
index=windowslogs | search Powershell
```

**`dedup`** – unique values by field

```spl
index=windowslogs 
| table EventID User Image Hostname 
| dedup EventID
```

**`rename`**

```spl
index=windowslogs 
| fields + host + User + SourceIp 
| rename User as Employees
```

---

### Ordering & Presentation

**`table`**

```spl
index=windowslogs | table EventID Hostname SourceName
```

**`head` / `tail`**

```spl
... | head          # default 10
... | head 5
... | tail 5
```

**`sort` / `reverse`**

```spl
... | sort Hostname
... | reverse
```

---

### Transforming / Stats / Charts

**`top` / `rare`**

```spl
index=windowslogs | top limit=7 Image
index=windowslogs | rare limit=7 Image
```

**`highlight`**

```spl
index=windowslogs | highlight User host EventID Image
```

**`stats`**

```spl
index=... | stats avg(product_price)
index=... | stats max(user_age)
index=... | stats min(product_price)
index=... | stats sum(product_cost)
index=... | stats count(source_IP)
```

**`chart`** (grouped stats)

```spl
index=windowslogs | chart count by User
```

**`timechart`** (time series)

```spl
index=windowslogs | timechart count by Image
```

---

## 3. Forwarders & Ingestion – Linux, Windows, Web

### On Linux

1. **Install Splunk Enterprise**
    

```bash
tar xvzf splunk_installer.tgz
mv splunk /opt/
cd /opt/splunk/bin
./splunk start --accept-license
# create admin user
```

2. **Install UF**
    

```bash
tar xvzf splunkforwarder.tgz
mv splunkforwarder /opt/
cd /opt/splunkforwarder
./bin/splunk start --accept-license
# if 8089 busy -> change to 8090
```

3. **On indexer (Splunk Web)**
    

- Settings → **Forwarding and receiving**
    
- Configure _Receiving_ → port **9997**.
    

4. **On forwarder**
    

```bash
cd /opt/splunkforwarder/bin
./splunk add forward-server MACHINE_IP:9997
./splunk add monitor /var/log/syslog -index Linux_host
```

Logs now ship from `/var/log/syslog` → index `Linux_host`.

---

### On Windows

1. Install **Splunk Enterprise** (GUI installer).
    
2. Access via: `http://127.0.0.1:8000` or `http://MACHINE_IP:8000`.
    
3. Install **Splunk Universal Forwarder**:
    
    - Accept license
        
    - Create forwarder account
        
    - (Optional) Deployment server
        
    - Set indexer IP + port `9997`.
        
4. In Splunk: Settings → **Forwarder Management** / **Add Data → Forwarders**
    
    - Choose **Local Event Logs** → select Security/System/etc
        
    - Create index → save.
        

---

### Web Logs (IIS)

- Web logs at:
    

```text
C:\inetpub\logs\LogFiles\W3SVC*
```

Flow:

1. Settings → Add Data → **Forward**.
    
2. Select **web host** as forwarder.
    
3. Configure path: `C:\inetpub\logs\LogFiles\W3SVC*`.
    
4. Set **sourcetype: iis** (or relevant).
    
5. Create **IIS index**.
    
6. Hit `http://coffely.thm` → generate traffic → logs show in index after a few minutes.
    

---

## 4. Reports, Dashboards, Alerts – SOC Workflow

### Reports

Use when you need **repeated searches** on a schedule.

Example:  
Count logins per VPN user:

```spl
host=vpn_server | stats count by Username
```

- Run once → **Save As → Report**.
    
- Choose:
    
    - Content: Statistics Table
        
    - Time Range Picker: Yes
        
    - Permissions: Private / Shared
        

Reports reduce load by running in staggered schedules and storing results.

---

### Dashboards

Use to **visualize** and combine multiple searches.

Steps:

1. Dashboards → Create Dashboard
    
    - Classic Dashboard
        
    - Permissions: _Shared in App_ if others must see it.
        
2. Add Panel → **New from Report**.
    
3. Select visualization: e.g. **Column Chart**.
    
4. Save (optionally set Dark theme).
    

Example: chart who logged in most:

```spl
host=vpn_server | stats count by Username
```

Dashboard instantly gives you “Sarah logs in the most, Emma the least” type insight.

---

### Alerts

Use when you need **real-time-ish detection**, not manual check.

Flow:

1. Run search (e.g. Sarah’s logins):
    

```spl
host=vpn_server Username=Sarah | stats count
```

2. Save As → **Alert**.
    
3. Configure:
    
    - Type: **Scheduled** (e.g. every hour).
        
    - Trigger condition:
        
        - `Number of Results is greater than 5`.
            
    - Throttle: e.g. `60 minutes` to avoid alert storms.
        
    - Trigger Actions:
        
        - Send email to `soc@tryhackme.com`
            
        - High priority, include results.
            

Now it pings you when thresholds are crossed.

---

## 5. Config Files & Stanzas – The Real Power

You walked through these:

- `inputs.conf` – what to ingest & how
    
- `props.conf` – how to parse / break / mask
    
- `transforms.conf` – more advanced transforms (you’ve touched but not fully used yet)
    
- `indexes.conf` – index definition, retention, paths
    
- `outputs.conf` – forwarding destinations
    
- `authentication.conf` – auth backends (e.g. LDAP)
    

---

### Typical `inputs.conf` (scripts)

Example – DataApp generating sample logs:

```ini
[script:///opt/splunk/etc/apps/DataApp/bin/samplelogs.py]
index = main
source = test_log
sourcetype = testing
interval = 5
```

VPN script:

```ini
[script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]
index = main
source = vpn
sourcetype = vpn_logs
interval = 5
```

Authentication logs:

```ini
[script:///opt/splunk/etc/apps/DataApp/bin/authentication_logs]
interval = 5
index = main
sourcetype = auth_logs
host = auth_server
```

Purchase logs:

```ini
[script:///opt/splunk/etc/apps/DataApp/bin/purchase-details]
interval = 5
index = main
source = purchase_logs
sourcetype = purchase_logs
host = order_server
```

---

## 6. Event Breaking & Multi-line Handling (props.conf)

### Case 1: VPN logs – break after CONNECT/DISCONNECT

Sample:

```text
User: Emily Davis, Server: Server C, Action: DISCONNECT
...
User: Michael Brown, Server: Server E, Action: CONNECT
```

**Problem**: Splunk merges multiple rows into single event.

**Fix:**

```ini
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)
```

Effect: Each line ending with `DISCONNECT` or `CONNECT` becomes a separate event.

---

### Case 2: Multi-line authentication logs – break only before `[Authentication]`

Sample event:

```text
[Authentication]:A login attempt was observed from the user Michael Brown and machine MAC_01
at: Mon Jul 17 08:10:12 2023 which belongs to the Custom department. The login attempt looks suspicious.
```

**Problem**: Splunk splits this into **two** events (each line separately).

**Fix:**

```ini
[auth_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Authentication\]
```

Effect:  
Any new line starting with `[Authentication]` marks a **new event**. All following lines belong to that event.

---

### Case 3: Purchase logs – break & mask card numbers

Sample:

```text
User William made a purchase with credit card 3714-4963-5398-4313.
...
User Bob Williams made a purchase with credit card 9876-5432-1098-7654.
```

**Step 1 – Fix event boundaries**

You used regex like `(3714-...|3530-...|...)` or a generic card pattern in `props.conf` with breaking stanzas (as per screenshots). The idea is the same: one purchase log = one event.

**Step 2 – Mask credit card PAN using `SEDCMD`**

You finalized:

```ini
[purchase_logs]
SEDCMD-mask_cc = s/-\d{4}-\d{4}-\d{4}/-XXXX-XXXX-XXXX/g
```

What it does:

- Finds patterns like: `-1234-5678-9012`
    
- Replaces them with: `-XXXX-XXXX-XXXX`
    

So:

```text
User Alice Johnson made a purchase with credit card 6011-1234-5678-9012.
```

becomes:

```text
User Alice Johnson made a purchase with credit card 6011-XXXX-XXXX-XXXX.
```

This keeps enough context (BIN/IIN) but masks the sensitive tail digits – **PCI DSS friendly**.

---

## 7. Tiny Cheat Sheet (for your brain & notes)

**Data flow**

- Source → UF/HF → Indexer (port 9997) → Index → Search Head.
    

**Linux UF**

```bash
./splunk add forward-server INDEXER_IP:9997
./splunk add monitor /var/log/syslog -index Linux_host
```

**Windows**

- Install Splunk Enterprise + UF.
    
- Configure receiving on port 9997.
    
- Add Data → Forwarder → Local Event Logs / IIS logs.
    

**Basic SPL**

```spl
index=windowslogs AccountName!=SYSTEM AND AccountName=James
index=windowslogs DestinationIp=172.*
| fields + host + User + SourceIp
| dedup EventID
| rename User as Employees
| table _time EventID Hostname SourceName
| head 5
| stats count by Username
| chart count by User
| timechart count by Image
```

**Event breaking / multi-line**

```ini
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)

[auth_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Authentication\]
```

**Masking (SEDCMD)**

```ini
[purchase_logs]
SEDCMD-mask_cc = s/-\d{4}-\d{4}-\d{4}/-XXXX-XXXX-XXXX/g
```

---
This is a fantastic, detailed walkthrough for a **Security Operations Center (SOC) analyst** on how to perform **custom field extraction in Splunk** using configuration files.

To complete the example and provide a comprehensive guide, I will fill in the missing configuration file content for the extraction of all three fields: **Username**, **Server**, and **Action**.

Here is the completed guide, following your structured steps:

## 🛡️ Custom Field Extraction in Splunk using Configuration Files

This process uses regular expressions (regex) and Splunk's configuration files (`transforms.conf`, `props.conf`, and `fields.conf`) to ensure that fields are extracted at **index time** for efficient analysis.

---

### 1. 📝 Creating the Master Regex Pattern

The goal is to capture all three fields from the sample logs:

User: John Doe, Server: Server C, Action: CONNECT

The complete regex pattern you provided is:

User:\s([\w\s]+),.+(Server.+),.+:\s(\w+)

- **Group 1 ($1):** `([\w\s]+)` captures the **Username** (e.g., `John Doe`).
    
- **Group 2 ($2):** `(Server.+)` captures the **Server** field (e.g., `Server C`).
    
- **Group 3 ($3):** `(\w+)` captures the **Action** (e.g., `CONNECT`).
    

---

### 2. ⚙️ Updating `transforms.conf`

This file defines the extraction method, using the regex and assigning the captured groups to specific field names.

The updated `transforms.conf` for `vpn_custom_fields` will look like this:

```
[vpn_custom_fields]
REGEX = User:\s([\w\s]+),.+(Server.+),.+:\s(\w+)
FORMAT = Username::$1 Server::$2 Action::$3
WRITE_META = true
```

#### Explanation of Updates:

- **`REGEX`**: Contains the full regex pattern to capture all three groups.
    
- **`FORMAT`**: This is the crucial part. It maps each captured group (`$1`, `$2`, `$3`) to a custom field name (`Username`, `Server`, `Action`).
    
    - `Username::$1` maps the first group to the `Username` field.
        
    - `Server::$2` maps the second group to the `Server` field.
        
    - `Action::$3` maps the third group to the `Action` field.
        

---

### 3. 📑 Updating `props.conf`

This file tells Splunk which configurations to apply to the specific `sourcetype` (`vpn_logs`). This step remains the same as in the initial process, linking the sourcetype to the identifier defined in `transforms.conf`.

The `props.conf` file should look like this (assuming you only had the single `TRANSFORM` line):

```
[vpn_logs]
TRANSFORM-vpn = vpn_custom_fields
```

---

### 4. 🔑 Updating `fields.conf`

This file instructs Splunk to extract and index the new fields for maximum search performance. You must list all three new fields.

The updated `fields.conf` will look like this:

```
[Username]
INDEXED = true

[Server]
INDEXED = true

[Action]
INDEXED = true
```

---

### 5. 🔄 Restart Splunk

As you mentioned, after making any changes to configuration files (`.conf`), a **Splunk restart** is mandatory for the changes to take effect.

### 6. ✅ Verification

After restarting, executing the search query:

index=main sourcetype=vpn_logs

You will now see the three custom fields—**Username**, **Server**, and **Action**—extracted and available in the **Fields Sidebar**, allowing for full analytical capabilities like statistical reports, filtering, and creating alerts.

---

