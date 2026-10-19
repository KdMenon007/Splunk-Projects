
---

## **Splunk Search & Reporting App — Core Functionalities (Straight Talk Edition)**

### **1) Search Head**

This is your command center.  
You run SPL queries here, slice through logs, and basically tell Splunk, “Yo, fetch.”  
All searching, visualizing, and pivoting happens from this interface.

---

### **2) Time Range Picker**

That little dropdown that decides _what slice of the universe_ you’re looking at.

- **All time** → full dataset (careful, this can hit performance hard).
    
- **Last 60 minutes** → quick behavioral snapshots.
    
- **Custom ranges** → go full detective mode.
    

Time filters are your best friend for narrowing noise.

---

### **3) Search History**

Splunk politely remembers everything you ran — timestamps included.

- Re-run old queries instantly
    
- Filter by keywords to hunt down a specific past search
    
- Great for analysts who repeat queries across incidents (aka everyone)
    

---

### **4) Data Summary**

Your “network visibility at a glance” dashboard.

Shows three main things:

- **Hosts** → who sent the data
    
- **Sources** → the file/log/device origin
    
- **Sourcetypes** → the format/structure Splunk assigned
    

This is perfect when you inherit a messy environment and need to orient yourself fast.

---

### **5) Field Sidebar**

Found on the left side of the Search Head — looks simple, but it's a gold mine.

#### **Selected Fields**

Default Splunk fields (host, source, sourcetype) plus any user-selected fields you’ve pinned for relevance.

#### **Interesting Fields**

Splunk auto-detects fields it thinks might matter based on frequency and structure.  
Great for exploring unknown datasets.

#### **Field Type Indicators**

- **α (alpha)** → contains text values
    
- **# (numeric)** → contains numbers
    

This helps you instantly know whether you’re dealing with counts, IPs, usernames, etc.

#### **Count Column**

Number next to each field = how many events contain that field.  
This is clutch for spotting anomalies, rare fields, or incomplete logs.

---

# **Splunk Search Processing Language (SPL) — Core Components Explained**

SPL is the engine room of Splunk. It’s made of functions, commands, operators, and eval expressions that let you transform raw machine data into actionable intelligence. Below are the foundational components that every analyst needs to understand.

---

## **1. Search Field Operators**

These are the basic filters used to build SPL queries.  
They help you narrow down results, eliminate noise, and target exactly the events you care about.

The main categories are:

- **Comparison operators**
    
- **Boolean operators**
    
- **Wildcards**
    

Let’s break each one down.

---

# **Comparison Operators**

Used to compare field values against specific criteria — numeric or string.

|Operator|Example|Meaning|
|---|---|---|
|**=**|`UserName=Mark`|Returns events where `UserName` equals "Mark".|
|**!=**|`UserName!=Mark`|Returns events where `UserName` is NOT "Mark".|
|**<**|`Age < 10`|Returns events with `Age` less than 10.|
|**<=**|`Age <= 10`|Returns events with `Age` ≤ 10.|
|**>**|`Outbound_traffic > 50`|Returns events where traffic exceeds 50.|
|**>=**|`Outbound_traffic >= 50`|Returns events where traffic is ≥ 50.|

### **Example Query**

Return all logs from index **windowslogs** where AccountName is _not_ "SYSTEM":

```
index=windowslogs AccountName!=SYSTEM
```

Clean and simple.

---

# **Boolean Operators**

Boolean operators help chain multiple conditions together. They’re essential for filtering, refining, or branching search logic.

|Operator|Syntax|Purpose|
|---|---|---|
|**NOT**|`field NOT value`|Excludes events containing the value.|
|**OR**|`field=value1 OR field=value2`|Matches either condition.|
|**AND**|`field=value1 AND field=value2`|Both conditions must be true.|

### **Example Query**

Show events where AccountName is NOT SYSTEM _and_ IS James:

```
index=windowslogs AccountName!=SYSTEM AND AccountName=James
```

---

# **Wildcards**

Wildcards let you match partial strings — extremely useful in messy, real-world logs.

|Wildcard|Example|Meaning|
|---|---|---|
|*****|`status=fail*`|Matches "failed", "failure", etc.|

### **Example Query**

Return all events where the DestinationIp starts with `172.`:

```
index=windowslogs DestinationIp=172.*
```

Useful for quickly isolating traffic within a particular subnet.

---

# **Filtering in SPL — The Commands Every Analyst Actually Uses**

When you’re dealing with thousands of logs per minute, you don’t _search_ in Splunk — you _hunt_. And hunts need filters. SPL gives us several commands to surgically remove noise and extract the exact telemetry we want.

Here’s the refined, accurate version of what you laid out.

---

# **1. `fields` Command**

### **Purpose**

Controls _which fields_ show up in your search output.

- Use **+** to _include_ fields.
    
- Use **–** to _exclude_ fields.
    

This is extremely helpful when the dataset is huge, or when you’re building dashboards, lookups, or reports.

### **Syntax**

```
| fields <field1> <field2> <field3>
```

### **Example**

Remove EventID, keep HostName:

```
| fields + HostName - EventID
```

### **Your Use Case**

Show only host, User, SourceIp:

```
index=windowslogs | fields + host + User + SourceIp
```

Pro tip: if fields aren’t visible in the results panel, hit the “More Fields” toggle — Splunk hides long lists to keep the UI clean.

---

# **2. `search` Command**

### **Purpose**

Used after a pipe (`|`) to filter events by _raw text_ (not field=value pairs).  
It’s like a “secondary filter” on the results of your main search.

### **Syntax**

```
| search <keyword>
```

### **Example**

```
| search "Powershell"
```

### **Your Use Case**

Return events that contain the term “Powershell” anywhere in the raw log:

```
index=windowslogs | search Powershell
```

Useful when you want to match strings _inside_ the event payload that may not be extracted as fields.

---

# **3. `dedup` Command**

### **Purpose**

Removes **duplicate values** for a given field.  
This is GOLD when you're trying to:

- list all unique usernames
    
- see unique EventIDs
    
- check unique IPs
    
- skim through hostnames without repetition
    

### **Syntax**

```
| dedup <fieldname>
```

### **Example**

```
| dedup EventID
```

### **Your Use Case**

Show unique EventIDs from a host:

```
index=windowslogs 
| table EventID User Image Hostname 
| dedup EventID
```

Remember:

- `dedup` keeps the **first** occurrence.
    
- `sort` before `dedup` if you want control over which “first” you keep.
    

---

# **4. `rename` Command**

### **Purpose**

Rename fields in the output — perfect for:

- report readability
    
- dashboard labels
    
- avoiding ambiguous names (e.g., "user" vs "src_user")
    

### **Syntax**

```
| rename <original_field> AS <new_name>
```

### **Example**

```
| rename User AS Employees
```

### **Your Use Case**

Rename User → Employees:

```
index=windowslogs 
| fields + host + User + SourceIp 
| rename User as Employees
```

Fast, clean, simple.

---

# **Structuring & Ordering Commands in SPL**

These SPL commands help analysts format, sort, trim, and reorganize search results. They’re essential for investigations, dashboards, exports, and quick visibility during triage.

---

# **1. `table` Command**

### **Purpose**

`table` lets you _choose exactly which fields_ appear in the results.  
It cleanly extracts only the fields you specify and hides everything else.

### **Syntax**

```
| table <field1> <field2> <field3>
```

### **Example**

```
index=windowslogs | table EventID Hostname SourceName
```

This outputs a table with _only_ EventID, Hostname, and SourceName as columns.

---

# **2. `head` Command**

### **Purpose**

Returns the **first** X number of events from the results.  
If you don’t specify a number, Splunk defaults to **10**.

### **Syntax**

```
| head <number>
```

### **Examples**

```
| head              # returns the first 10 events
| head 20           # returns the first 20 events
```

### **Use Case**

Show the first 5 events after tabling the fields:

```
index=windowslogs 
| table _time EventID Hostname SourceName 
| head 5
```

---

# **3. `tail` Command**

### **Purpose**

Returns the **last** X number of events from the results.  
Default is **10** if no number is provided.

### **Syntax**

```
| tail <number>
```

### **Examples**

```
| tail              # last 10 events
| tail 20           # last 20 events
```

### **Use Case**

Get the _last_ 5 events from your table:

```
index=windowslogs 
| table _time EventID Hostname SourceName 
| tail 5
```

---

# **4. `sort` Command**

### **Purpose**

Sorts results based on a field — ascending or descending.

### **Syntax**

```
| sort <fieldname>
| sort - <fieldname>      # descending
| sort + <fieldname>      # ascending (default)
```

### **Examples**

```
| sort Hostname           # ascending order
| sort - EventID          # descending
```

### **Use Case**

```
index=windowslogs 
| table _time EventID Hostname SourceName 
| sort Hostname
```

---

# **5. `reverse` Command**

### **Purpose**

Simply flips the order of the results.  
Great when you want to switch from newest-first → oldest-first or vice versa _without_ re-running the whole search.

### **Syntax**

```
| reverse
```

### **Example**

```
index=windowslogs 
| table _time EventID Hostname SourceName 
| reverse
```

---



---

## Additional evidence received — lookup enrichment and VPN login anomaly

### Image risk-score lookup

Screenshot `21-image-risk-score-lookup.png` shows this SPL: `index=windowslogs | lookup image_riskscore Image OUTPUT RiskScore | stats count by Image RiskScore | sort - RiskScore`. The event view reports 12,256 events and the Image field summary lists 35 values. The screenshot does not show the lookup definition or the full stats output. Validate lookup key/output field names, score type, and unmatched-image behavior.

### VPN login-hour anomaly

Screenshot `22-vpn-login-hour-zscore-anomaly.png` shows a per-user average and standard deviation of decimal login hour, followed by a z-score threshold greater than 3. Two rows are displayed: `njackson` with z-score 5.49 and `jsmith` with z-score 3.01. These are candidates for further investigation, not proof of compromise. The query sorts on `hour_zscore`, but creates `zscore`; likely intended sort is `| sort - zscore`. The approach also needs safeguards for zero/low standard deviation and the circular nature of time-of-day.
