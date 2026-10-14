
---

# 🧩 **Splunk Architecture — The Three Core Components**

Splunk operates using **three main building blocks**:

|Component|What It Does|Where It Lives|
|---|---|---|
|**Forwarder**|Collects & sends logs|On endpoints / servers|
|**Indexer**|Parses, normalizes, and stores logs|On Splunk server|
|**Search Head**|Allows searching, dashboards, alerts|Web interface for analysts|

They work together as a pipeline:

```
Endpoints → (Forwarder) → Indexer → Search Head (Analyst)
```

![[Pasted image 20251106102058.png]]

---

## 1) **Splunk Forwarder** (The Data Collector)

This is a **lightweight agent** installed on machines you want to monitor.  
Its job is simple:

✅ **Collect logs**  
✅ **Send them to Indexer**  
❌ Does **not** analyze or visualize anything

### Common Data Sources Forwarders Monitor:

- **Web servers** → access/error logs
    
- **Windows endpoints** → Event Logs, Sysmon, PowerShell logs
    
- **Linux hosts** → `/var/log/*`
    
- **Databases** → connections, queries, errors
    

> Key idea: The forwarder **ships logs in real time** with minimal performance impact.

![[Pasted image 20251106102108.png]]

---

## 2) **Splunk Indexer** (The Brain & Storage Engine)

This is where logs are **processed**:

### What the Indexer Does:

|Action|Meaning|
|---|---|
|**Parses** logs|Breaks logs into pieces|
|**Normalizes** logs|Turns logs into **field=value** format|
|**Indexes** data|Stores events efficiently for search|
|**Categorizes** data|Organized into indexes (different buckets)|

> This is why Splunk searches feel fast — the data is stored in a structure optimized for querying.

![[Pasted image 20251106102121.png]]

---

## 3) **Search Head** (Where Analysts Live)

This is the **web UI** where you:

- Query the indexed data
    
- Build dashboards
    
- Create alerts
    
- Investigate incidents
    

![[Pasted image 20251106102130.png]]

![[Pasted image 20251106102138.png]]


### Uses **SPL (Search Processing Language)**

It’s Splunk’s query language for searching events.

Example SPL:

```
index=vpn_logs eventtype=login_fail user="jsmith"
```

The Search Head sends the query to the Indexer → Indexer returns matching events.

You can also generate:

- Tables
    
- Charts (Pie / Bar / Timecharts)
    
- Custom dashboards
    

---

# 🖥 Navigating the Splunk UI

When you log in, the home screen contains several key sections:

![[Pasted image 20251106102222.png]]

### **Splunk Bar (Top Panel)**

|Button|Purpose|
|---|---|
|**Messages**|System notifications|
|**Settings**|Manage users, inputs, indexes, parsing rules|
|**Activity**|See your running searches|
|**Help**|Docs + tutorials|
|**Find**|Search for apps/features|

It also lets you **switch between Splunk Apps** quickly.

---

### **Apps Panel**

Shows installed Splunk apps (e.g., **Search & Reporting**).  
Think of apps as **collections of dashboards + visualizations + field mappings**.

---

### **Explore Splunk Section**

Quick access to:

- **Add data** (file upload, log ingestion config)
    
- **Install new Splunk apps**
    
- **Open documentation**
    

---

### **Home Dashboard**

Initially empty — you can:

- Load existing dashboards
    
- Create your own & pin to Home
    
- Switch between **All / Yours**
    

---

# 📥 Data Ingestion in Splunk

When data is added to Splunk:

1. It is **broken into individual events**
    
2. Fields are **extracted**
    
3. Events are stored and made **searchable**
    

### Splunk supports many data source categories:

- Windows logs
    
- Network firewall logs
    
- Web server logs
    
- Security device logs
    
- VPN logs (our focus in this task)
    
- Application logs
    
- Cloud logs (AWS/Azure/GCP)
    

---

# ⬆️ Uploading Data (Scenario: VPN Logs)

From **Home Screen → Add Data**:

You’ll see 3 main ingestion methods:

1. **Upload** (local file) ← _We use this here_
    
2. **Monitor** (real-time local file/directory)
    
3. **Forward** (via Splunk Forwarder)
    

For this task, we choose **Upload** to import VPN logs directly from the machine.

---

# ✅ Key Takeaways (Everything You Need to Remember)

|Concept|Summary|
|---|---|
|Splunk Forwarder|Collects logs from endpoints → sends to Indexer|
|Splunk Indexer|Parses, normalizes, indexes, and stores log events|
|Splunk Search Head|Allows analysts to query data using SPL + dashboards|
|Splunk UI Sections|Splunk Bar, Apps Panel, Explore Section, Home Dashboard|
|Data Ingestion|Upload → Parse → Normalize → Store → Search|

Splunk = **Collect → Index → Search → Analyze → Visualize**

---

