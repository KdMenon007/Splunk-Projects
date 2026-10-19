## Don't memorize paragraphs

For example, don't memorize Q999 word-for-word.

Turn the entire investigation methodology into:

**V → E → T → P → S → I → M → R → D**

```text
Validate
   ↓
Entities
   ↓
Timeline
   ↓
Pivot
   ↓
Scope
   ↓
Impact
   ↓
MITRE
   ↓
Response
   ↓
Document
```

## What MUST be memorized

Some things are worth literal memorization:

**Windows Event IDs**

```text
4624 → Successful logon
4625 → Failed logon
4648 → Explicit credentials
4672 → Special privileges
4688 → Process creation
4698 → Scheduled task
4720 → Account created
4728/4732 → Group membership
4740 → Account lockout
4769 → Kerberos service ticket
```

**Core SPL**

```spl
stats
dc()
values()
eval
where
rex
timechart
bin
dedup
sort
lookup
eventstats
streamstats
tstats
```

And know what each does rather than only remembering syntax.

**Splunk architecture**

```text
Source
→ Forwarder
→ Indexer
→ Search Head
→ Analyst
```

**CIM / ES**

```text
Raw data
→ Extraction
→ Normalization
→ CIM
→ Data Model
→ tstats
→ Detection
→ Notable
```

---
## 1. What is Splunk?

**Answer:**

> Splunk is a platform that collects, indexes, searches, analyzes, and visualizes machine-generated data. In a SOC, we use it to centralize security telemetry such as Windows events, Linux logs, firewall logs, DNS, VPN, proxy, EDR, and authentication data.

**Follow-up:**  
**Why is Splunk useful to a SOC?**

> Because I can correlate activity across multiple data sources and build an attack timeline instead of investigating each log source independently.

---

## 2. What is SPL?

**Answer:**

> SPL stands for Search Processing Language. It's used to search and transform Splunk data, perform statistical analysis, extract fields, correlate events, and create security detections.

Example:

```spl
index=windows EventCode=4625
| stats count by user, src_ip
| sort - count
```

This identifies users and source IPs generating failed authentication events.

**Follow-up:**  
**Is SPL the same as SQL?**

> No. Both query data, but SPL is designed around event-based search and streaming/transformational processing.

---

# 3. What is an event?

**Answer:**

An event is an individual piece of data representing something that happened.

Example:

```text
Time: 10:30
User: john
Source IP: 10.10.10.50
Action: Login Success
Host: SERVER01
```

In SOC investigation, each event can become a pivot point.

---

# 4. What is `_raw`?

**Answer:**

`_raw` contains the original/raw event data ingested into Splunk.

If a field isn't extracted correctly, I may inspect `_raw` to determine whether the information exists and can be extracted.

---

# 5. What is `_time`?

**Answer:**

`_time` represents the timestamp associated with the event.

It's extremely important during incident investigation because I use it to construct the attack timeline.

---

# 6. What is an index?

**Answer:**

An index is a logical storage location for Splunk data.

For example:

```text
index=windows
index=linux
index=firewall
index=dns
index=edr
```

Instead of searching everything, I normally scope my search to the relevant index.

---

# 7. What is a sourcetype?

**Answer:**

A sourcetype identifies the type or format of data.

For example:

```text
WinEventLog:Security
linux_secure
```

The sourcetype helps Splunk understand how to interpret the incoming events.

---

# 8. Difference between index and sourcetype?

**Answer:**

Think:

```text
INDEX     = Where the data is stored
SOURCETYPE = What type of data it is
```

Example:

```spl
index=windows sourcetype=WinEventLog:Security
```

---

# 9. What is a source?

**Answer:**

Source identifies where the event originated.

For example, it could represent a log file, network input, or another input source.

---

# 10. What is a host?

**Answer:**

Host identifies the system that generated the event.

Example:

```text
host=DC01
host=WEB01
host=LINUX01
```

---

# 11. What is a field?

**Answer:**

A field is a structured attribute extracted from an event.

Examples:

```text
user
src_ip
dest_ip
dest_port
action
process_name
```

Fields allow us to search and correlate data efficiently.

---

# 12. Why are fields important in SOC investigations?

**Answer:**

Because fields let me pivot quickly.

For example:

```text
Suspicious IP
     ↓
src_ip
     ↓
user
     ↓
host
     ↓
process
     ↓
destination
```

Without reliable fields, investigation becomes much harder.

---

# 13. What is a Search Head?

**Answer:**

A Search Head provides the search interface and coordinates searches across Splunk infrastructure.

For an analyst, this is generally where we execute SPL and analyze results.

---

# 14. What is an Indexer?

**Answer:**

An indexer processes and stores Splunk data and participates in search execution.

Simple model:

```text
Data
 ↓
Indexer
 ↓
Storage/Search
```

---

# 15. What is a Forwarder?

**Answer:**

A forwarder collects data from systems and sends it to Splunk processing/storage components.

Example:

```text
Windows Server
      ↓
Universal Forwarder
      ↓
Indexer
```

---

# 16. What is a Universal Forwarder?

**Answer:**

A Universal Forwarder is a lightweight Splunk component primarily used to collect and forward data.

It's commonly deployed on endpoints and servers.

---

# 17. What is a Heavy Forwarder?

**Answer:**

A Heavy Forwarder is a more capable Splunk instance that can perform additional processing, routing, and data handling compared with a Universal Forwarder.

---

# 18. Universal Forwarder vs Heavy Forwarder?

|Universal Forwarder|Heavy Forwarder|
|---|---|
|Lightweight|More resource intensive|
|Primarily forwarding|Can perform more processing|
|Common on endpoints|Used for specialized collection/routing|
|Minimal footprint|Broader Splunk capabilities|

---

# 19. Explain basic Splunk architecture.

**Answer:**

```text
Windows ───┐
Linux ─────┤
Firewall ──┤
DNS ───────┤
EDR ───────┤
VPN ───────┘
     ↓
Forwarder / Collector
     ↓
Indexer
     ↓
Index
     ↓
Search Head
     ↓
SOC Analyst
```

---

# 20. What happens when data enters Splunk?

**Answer:**

At a high level:

```text
Collection
   ↓
Parsing
   ↓
Indexing
   ↓
Storage
   ↓
Search
   ↓
Analysis
```

The exact architecture depends on the deployment.

---

# 21. What is distributed search?

**Answer:**

Distributed search allows a search head to execute searches across multiple indexers.

This allows Splunk to scale search workloads.

---

# 22. What is an indexer cluster?

**Answer:**

An indexer cluster is a group of indexers designed to provide distributed storage, search capability, scalability, and availability.

---

# 23. What is replication factor?

**Answer:**

Replication factor indicates how many copies of indexed data are maintained within an indexer cluster.

Its purpose is primarily resilience and availability.

---

# 24. What is search factor?

**Answer:**

Search factor represents how many copies of data are maintained in a searchable state within an indexer cluster.

---

# 25. What is a Search Head Cluster?

**Answer:**

A Search Head Cluster consists of multiple search heads working together to provide scalability and availability.

---

# 26. What is a Splunk dashboard?

**Answer:**

A dashboard presents search results and visualizations in a consolidated interface.

SOC examples:

```text
Critical Alerts
Failed Logins
Top Attacking IPs
Malware Alerts
High-Risk Hosts
DNS Anomalies
Outbound Traffic
```

---

# 27. What is an alert?

**Answer:**

An alert is generated when defined search conditions are met.

Example:

```text
More than 50 failed logins
from one source
within 5 minutes
```

That could trigger a SOC alert.

---

# 28. What is a scheduled search?

**Answer:**

A scheduled search automatically executes at a configured interval.

Example:

```text
Every 5 minutes
       ↓
Search failed logins
       ↓
Threshold exceeded?
       ↓
Generate alert
```

---

# 29. What is a correlation search?

**Answer:**

A correlation search identifies security-relevant patterns by combining conditions or events.

Example:

```text
50 failed logins
       +
Successful login
       +
PowerShell
```

The combined behavior may be more suspicious than any individual event.

---

# 30. What is a notable event?

**Answer:**

In Splunk Enterprise Security, a notable event represents a security finding requiring investigation.

Example:

```text
Potential Brute Force Attack
```

The analyst investigates the underlying evidence.

---

# 31. What is Splunk Enterprise Security?

**Answer:**

Splunk Enterprise Security is a security-focused solution built on Splunk capabilities.

It provides features such as:

- Notable events
    
- Correlation searches
    
- Risk analysis
    
- Asset context
    
- Identity context
    
- Threat intelligence
    
- Security investigation workflows
    

---

# 32. What is a SIEM?

**Answer:**

A SIEM collects and analyzes security events from multiple sources to support detection, investigation, monitoring, and response.

---

# 33. Is Splunk a SIEM?

**Answer:**

A good interview answer:

> Splunk is a broader data platform. With Splunk Enterprise Security, it provides comprehensive SIEM capabilities for security monitoring, detection, investigation, and response.

---

# 34. Why use Splunk instead of checking every device individually?

**Answer:**

Because centralized telemetry allows:

```text
Windows
Linux
Firewall
DNS
VPN
EDR
Proxy
   ↓
 Splunk
   ↓
Correlation
```

Instead of manually checking six different systems.

---

# 35. What is data onboarding?

**Answer:**

Data onboarding is the process of bringing a new data source into Splunk and making it usable for searches and detections.

It involves:

```text
Collection
 ↓
Parsing
 ↓
Indexing
 ↓
Field extraction
 ↓
Normalization
 ↓
Validation
```

---

# 36. Scenario: Your company gets a new firewall. How would you onboard it?

**Answer:**

I'd first identify the firewall's supported collection method, such as syslog or an integration.

Then:

```text
Firewall
 ↓
Collection
 ↓
Splunk
 ↓
Correct index
 ↓
Correct sourcetype
 ↓
Field extraction
 ↓
Validation
```

I'd verify fields such as:

```text
src_ip
dest_ip
src_port
dest_port
action
protocol
bytes
```

Then test searches and detections.

---

# 37. Scenario: Windows logs suddenly disappear from Splunk. What do you check?

**Answer:**

I would troubleshoot the entire pipeline:

```text
Windows Event Log
       ↓
Forwarder
       ↓
Network
       ↓
Indexer
       ↓
Index
       ↓
Search
```

I'd check:

- Windows logging
    
- Forwarder service
    
- Connectivity
    
- Configuration
    
- Index
    
- Sourcetype
    
- Timestamp
    
- Ingestion delay
    

I wouldn't immediately conclude that Splunk is broken.

---

# 38. Scenario: You know logs exist, but your search returns nothing.

**Answer:**

I'd check:

1. Time range
    
2. Index
    
3. Sourcetype
    
4. Host
    
5. Field names
    
6. Field values
    
7. Timestamp
    
8. Data ingestion
    
9. Parsing
    

Example:

```spl
index=windows
host=DC01
earliest=-24h
```

Then narrow the search.

---

# 39. What is telemetry?

**Answer:**

Telemetry is security-relevant data generated by systems, applications, endpoints, network devices, identity systems, and security tools.

Examples:

```text
Windows events
DNS queries
Firewall connections
EDR process events
VPN authentication
Proxy requests
```

---

# 40. Why is telemetry quality important?

**Answer:**

Because detections are only as good as the underlying telemetry.

Bad telemetry can cause:

```text
Missing logs
     ↓
Missed detection

Bad parsing
     ↓
Broken searches

Wrong timestamps
     ↓
Incorrect timeline
```

---

# 41. What is telemetry coverage?

**Answer:**

Telemetry coverage describes whether the required systems and security-relevant activities are actually generating usable data.

---

# 42. Scenario: An attacker is suspected, but there are no endpoint logs.

What do you do?

**Answer:**

I wouldn't conclude that nothing happened.

I'd look for alternative evidence:

```text
Authentication
Firewall
DNS
Proxy
VPN
Network flow
Cloud logs
Identity logs
```

I'd also investigate why endpoint telemetry is missing.

---

# 43. What is a false positive?

**Answer:**

A false positive occurs when a detection identifies activity as suspicious but investigation determines it is legitimate.

Example:

```text
100 SSH attempts
```

could be:

```text
Attack
```

or:

```text
Authorized vulnerability scanner
```

---

# 44. What is a true positive?

**Answer:**

A true positive occurs when the detection correctly identifies malicious or genuinely security-relevant activity.

---

# 45. Alert vs Incident?

**Answer:**

An alert is a signal generated by a detection.

An incident is a confirmed or suspected security event that requires investigation and potentially response.

Think:

```text
Alert
 ↓
Investigation
 ↓
Evidence
 ↓
Incident?
```

---

# 46. Why shouldn't an analyst immediately label an alert "malicious"?

**Answer:**

Because the alert represents a detection condition, not necessarily confirmed malicious activity.

I need to validate:

```text
Context
Timeline
User
Host
IP
Process
Business activity
Other telemetry
```

---

# 47. What is alert triage?

**Answer:**

Alert triage is the process of quickly determining:

```text
Is it real?
How serious?
What happened?
Who/what is affected?
What should happen next?
```

---

# 48. What determines alert priority?

**Answer:**

I consider:

```text
Confidence
+
Impact
+
Asset criticality
+
User privilege
+
Scope
+
Active compromise
```

For example, the same failed login pattern against a test workstation and a Domain Controller should not necessarily receive the same priority.

---

# 49. What is enrichment?

**Answer:**

Enrichment means adding useful context to an event.

For example:

```text
IP
 ↓
Asset lookup
 ↓
Owner = Finance
Criticality = High
```

Other enrichment could include:

- Threat intelligence
    
- User role
    
- Geo information
    
- Asset type
    
- Reputation
    

---

# 50. How would you investigate ANY Splunk security alert?

### ⭐ Best interview answer

> "First, I would understand what triggered the alert and validate whether the underlying event is present. Then I'd identify the key entities such as user, host, source IP, destination IP, process, and timestamp. I'd establish an appropriate investigation window and build a timeline. Next, I'd pivot across relevant telemetry such as authentication, endpoint, DNS, firewall, proxy, and network logs. I'd determine whether the behavior is legitimate or malicious, identify the scope and potential impact, and map the observed behavior to MITRE ATT&CK where appropriate. If compromise is confirmed, I'd follow the organization's incident-response playbook and my authorization level for containment or escalation. Finally, I'd document the evidence, queries, timeline, conclusion, and any detection-tuning opportunities."

### Interviewer follow-up:

**"Can you give me an example?"**

Say:

> "For example, if I receive a brute-force alert, I wouldn't stop after seeing failed logins. I'd identify the source and targeted accounts, check whether authentication eventually succeeded, investigate what happened after the successful login, and correlate process, DNS, firewall and endpoint activity. That tells me whether I'm dealing with an attempted attack, a successful compromise, or legitimate activity."

---

# 🔥 Your First 50 — What You Must Be Able To Do

After Part 1, you should be able to explain:

```text
                 SPLUNK
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
     DATA         SEARCH       SECURITY
       │            │            │
       ▼            ▼            ▼
   Index         SPL          Alerts
   Host          Stats        Notables
   Source        Fields       Correlation
   Sourcetype    Time         Risk
       │            │            │
       └────────────┼────────────┘
                    ▼
               INVESTIGATION
                    │
                    ▼
                TIMELINE
                    │
                    ▼
               CORRELATION
                    │
                    ▼
             DECISION / RESPONSE
```

### The key distinction

A beginner says:

> **"I know Splunk and I know SPL."**

An interview-ready SOC analyst says:

> **"I can use Splunk to investigate an alert, formulate a hypothesis, pivot through telemetry, correlate events, determine whether the behavior is malicious, scope the incident, and explain the evidence behind my conclusion."**

---

# SECTION A — SPLUNK ARCHITECTURE

## 51. Explain Splunk architecture end-to-end.

**Answer:**

At a high level:

```text
Data Sources
     ↓
Collection / Forwarder
     ↓
Indexer
     ↓
Index
     ↓
Search Head
     ↓
SOC Analyst
```

Example:

```text
Windows DC
Firewall
Linux Server
DNS
EDR
   ↓
Collection
   ↓
Splunk
   ↓
Search
   ↓
Detection
   ↓
Investigation
```

---

## 52. What is the role of a forwarder?

**Answer:**

A forwarder collects data from a source and forwards it to the appropriate Splunk receiving component.

Example:

```text
Windows Server
      ↓
Universal Forwarder
      ↓
Indexer
```

---

## 53. What is the role of an indexer?

**Answer:**

The indexer processes and stores Splunk data and makes that data available for searches.

Think:

> **Forwarder = moves data**  
> **Indexer = stores/processes data**  
> **Search Head = coordinates searches**

---

## 54. What is the role of the Search Head?

**Answer:**

The Search Head provides the search interface and coordinates searches against indexed data.

As an analyst, this is where I commonly execute SPL and analyze results.

---

## 55. What happens if the Search Head goes down?

**Answer:**

Search functionality through that Search Head may become unavailable, depending on the deployment architecture. In a properly designed Search Head Cluster, another member can provide availability.

---

## 56. What happens if an indexer goes down?

**Answer:**

In a clustered deployment, replication can provide resilience. The exact behavior depends on cluster configuration and the availability of searchable replicated copies.

---

## 57. Why use an indexer cluster?

**Answer:**

For:

- Scalability
    
- Data availability
    
- Distributed storage
    
- Search workload distribution
    
- Resilience
    

---

## 58. Why use a Search Head Cluster?

**Answer:**

To provide:

- Search availability
    
- Scalability
    
- Shared configuration/state
    
- Load distribution
    

---

## 59. What is distributed search?

**Answer:**

A Search Head can distribute a search across multiple indexers and combine the results.

Example:

```text
                 Search Head
                      |
           ┌──────────┼──────────┐
           ↓          ↓          ↓
       Indexer 1  Indexer 2  Indexer 3
           |          |          |
           └──────────┼──────────┘
                      ↓
                 Search Result
```

---

## 60. What is replication factor?

**Answer:**

Replication factor represents how many copies of indexed data are maintained within an indexer cluster.

Its purpose is resilience.

---

## 61. What is search factor?

**Answer:**

Search factor represents how many copies of data are maintained in a searchable state.

---

## 62. What is a deployment server?

**Answer:**

A deployment server can centrally distribute configuration and apps to supported Splunk instances, commonly forwarders.

---

## 63. What is a receiving port?

**Answer:**

It is a network port on which a Splunk instance accepts forwarded data.

The exact port depends on the environment's configuration.

---

## 64. What is a forwarder configuration?

**Answer:**

It defines things such as:

```text
What data to collect
Where to send it
How to route it
Relevant source configuration
```

---

## 65. What is `inputs.conf`?

**Answer:**

`inputs.conf` defines data inputs, such as files, Windows Event Logs, scripts, network inputs, and other collection mechanisms.

---

## 66. What is `outputs.conf`?

**Answer:**

`outputs.conf` defines forwarding destinations and related forwarding configuration.

---

## 67. What is `props.conf`?

**Answer:**

`props.conf` controls behavior associated with sourcetypes and data processing, including parsing and field-related configuration depending on deployment.

---

## 68. What is `transforms.conf`?

**Answer:**

`transforms.conf` defines transformations used for routing, field extraction, masking, lookups, and other processing depending on configuration.

---

## 69. What is a Splunk app?

**Answer:**

An app is a package containing configuration, searches, dashboards, knowledge objects, and other functionality for a specific purpose.

---

## 70. Why use vendor Splunk apps/add-ons?

**Answer:**

They can provide predefined parsing, field extractions, dashboards, detections, and normalization for supported products.

---

# SECTION B — DATA INGESTION

## 71. What is data ingestion?

**Answer:**

Data ingestion is the process of collecting external data and bringing it into Splunk for indexing and analysis.

---

## 72. What are common security data sources?

**Answer:**

```text
Windows
Linux
Firewall
IDS/IPS
EDR
DNS
Proxy
VPN
Email
Cloud
Identity providers
Applications
```

---

## 73. How would you onboard Windows security logs?

**Answer:**

I would:

```text
1. Enable required Windows auditing
2. Configure collection
3. Forward events
4. Assign correct index/sourcetype
5. Validate ingestion
6. Validate fields
7. Test searches
8. Test detections
```

---

## 74. How would you onboard Linux logs?

**Answer:**

Collect relevant authentication/system/audit telemetry, forward it, configure the appropriate index and sourcetype, validate timestamps and fields, and test searches.

---

## 75. How would you onboard firewall logs?

**Answer:**

First identify the supported collection mechanism, such as syslog or an integration.

Then:

```text
Firewall
   ↓
Syslog / Collector
   ↓
Splunk
   ↓
Index
   ↓
Sourcetype
   ↓
Field extraction
   ↓
Validation
```

---

## 76. What fields do you expect from firewall data?

**Answer:**

Depending on the firewall:

```text
src_ip
dest_ip
src_port
dest_port
protocol
action
bytes
timestamp
rule
interface
```

---

## 77. What fields do you expect from DNS?

**Answer:**

Potential fields include:

```text
src_ip
query
answer
response_code
record_type
dest_ip
timestamp
```

Exact fields depend on the data source.

---

## 78. What fields do you expect from authentication?

**Answer:**

Common concepts include:

```text
user
src_ip
dest
action
authentication_method
status
timestamp
```

---

## 79. What fields do you expect from EDR?

**Answer:**

Potentially:

```text
host
user
process_name
parent_process
command_line
file_hash
file_path
src_ip
dest_ip
action
```

---

## 80. Why is field consistency important?

**Answer:**

If different sources use different field names for the same concept, correlation and detection become harder.

For example:

```text
src_ip
source_ip
client_ip
```

should ideally be normalized appropriately.

---

# SECTION C — PARSING

## 81. What is parsing?

**Answer:**

Parsing is the processing of incoming data so Splunk can identify event boundaries, timestamps, metadata, and other structured information.

---

## 82. What is event breaking?

**Answer:**

Event breaking determines where one event ends and another begins.

---

## 83. Why is event breaking important?

**Answer:**

If multiple events are incorrectly combined, or one event is incorrectly split into many events, investigations and detections can become unreliable.

---

## 84. What happens if event timestamps are wrong?

**Answer:**

Attack timelines become unreliable.

Example:

```text
Real event:
10:00

Splunk:
15:30
```

This can cause analysts to miss correlations.

---

## 85. What is timezone handling?

**Answer:**

Timezone configuration determines how timestamps are interpreted and represented.

Incorrect timezone handling can shift events and break timeline analysis.

---

## 86. Scenario: Logs are arriving but `_time` is wrong.

What do you do?

**Answer:**

I would check:

```text
Source timestamp
Timezone
Timestamp extraction
Parsing configuration
Host clock
NTP/time synchronization
```

Then validate with known events.

---

## 87. Scenario: One firewall log appears as three events.

What could be wrong?

**Answer:**

Potentially incorrect event-breaking configuration or parsing.

I'd inspect `_raw`, sourcetype, source format, and event-boundary configuration.

---

## 88. Scenario: Ten firewall events appear as one event.

What could be wrong?

**Answer:**

Again, likely event-breaking/parsing issues.

I'd inspect the raw event structure and parsing configuration.

---

## 89. Why is `_raw` useful?

**Answer:**

It allows me to verify what Splunk actually received.

For example, if:

```spl
src_ip
```

is missing, I can inspect `_raw` to see whether the IP exists but wasn't extracted.

---

## 90. How do you troubleshoot a missing field?

**Answer:**

```text
Search event
   ↓
Inspect _raw
   ↓
Does data exist?
   ↓
Yes → extraction/parsing problem
No  → source/collection problem
```

---

# SECTION D — FIELD EXTRACTION

## 91. What is field extraction?

**Answer:**

Field extraction converts information from raw events into structured searchable fields.

Example raw data:

```text
src=10.10.10.25 dst=192.168.1.10
```

Extracted:

```text
src_ip=10.10.10.25
dest_ip=192.168.1.10
```

---

## 92. What is `rex`?

**Answer:**

`rex` can extract fields from event text using regular expressions.

Example:

```spl
| rex "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
```

---

## 93. When would you use `rex`?

**Answer:**

When the required information exists in the event but isn't already available as a usable field.

---

## 94. Should you always use `rex`?

**Answer:**

No.

If the field is already properly extracted, use the existing field. Repeated runtime regex extraction can be unnecessary and less efficient.

---

## 95. What is automatic field extraction?

**Answer:**

Splunk can extract fields automatically or through configured knowledge objects depending on the data format and configuration.

---

## 96. What if a field exists in some events but not others?

**Answer:**

I'd investigate:

- Different sourcetypes
    
- Vendor format differences
    
- Parsing changes
    
- Missing source data
    
- Field extraction inconsistencies
    

---

## 97. Scenario: Firewall changed vendors and your detection stopped working.

What do you check?

**Answer:**

I would compare the old and new event structures and verify:

```text
Index
Sourcetype
Field names
Field values
Timestamp
Parsing
CIM normalization
```

Then update or normalize the detection appropriately.

---

## 98. Why shouldn't detections depend blindly on raw text?

**Answer:**

Raw formats can change. Structured normalized fields are generally more maintainable and reusable.

---

## 99. What is field normalization?

**Answer:**

Representing equivalent concepts from different data sources using consistent field names and structures.

---

## 100. Why is normalization important?

**Answer:**

It allows a detection to operate across multiple vendors.

For example:

```text
Firewall A → src_ip
Firewall B → source_address
Firewall C → client_ip
```

can be normalized to a common representation.

---

# SECTION E — CIM

## 101. What is CIM?

**Answer:**

CIM stands for Common Information Model.

It provides standardized field definitions and data models for common security and operational data types.

---

## 102. Why is CIM important?

**Answer:**

It allows security searches and detections to operate more consistently across different data sources and vendors.

---

## 103. Give an example of CIM normalization.

Suppose:

```text
Vendor A:
sourceAddress

Vendor B:
src

Vendor C:
clientIP
```

They can be normalized conceptually to:

```text
src
```

or the appropriate CIM field.

---

## 104. Why is CIM useful for SOC analysts?

**Answer:**

It reduces the need to rewrite every detection for every vendor.

---

## 105. What happens if data isn't CIM compliant?

**Answer:**

Some ES detections, data-model searches, and normalized analytics may not work correctly or may miss events.

---

## 106. Scenario: Firewall data is visible, but a CIM-based detection doesn't see it.

What do you investigate?

**Answer:**

I would check:

```text
Correct index?
Correct sourcetype?
Required fields present?
Correct field names?
CIM mapping?
Data model acceleration?
Timestamp?
```

---

## 107. Why is CIM especially useful in large organizations?

**Answer:**

Large environments often have multiple vendors providing similar telemetry. Normalization allows common analytics across those sources.

---

## 108. Does CIM change the original raw data?

**Answer:**

Conceptually, CIM is about normalization and data modeling rather than changing the original event itself.

---

## 109. Does every field need to be CIM normalized?

**Answer:**

No. The relevant fields needed for the particular data model/use case should be normalized.

---

## 110. What is a data model?

**Answer:**

A data model organizes normalized data into structured datasets that support efficient analytics and searches.

---

# SECTION F — TROUBLESHOOTING SCENARIOS

## 111. Windows logs completely disappear.

### What do you do?

**Answer:**

```text
1. Is Windows generating events?
2. Is the forwarder running?
3. Is the endpoint connected?
4. Is data leaving the endpoint?
5. Is the receiving destination reachable?
6. Is the correct index configured?
7. Is the sourcetype correct?
8. Is ingestion delayed?
9. Are timestamps valid?
```

---

## 112. Only one Windows host stops sending logs.

**Answer:**

I would focus first on that endpoint:

```text
Windows Event Log
Forwarder
Configuration
Connectivity
Service status
Disk/resources
```

---

## 113. Every Windows host stops sending logs.

**Answer:**

I'd investigate shared infrastructure:

```text
Forwarding configuration
Indexer/collector
Network
Certificate/authentication
Deployment configuration
Splunk infrastructure
```

---

## 114. Only one sourcetype disappears.

**Answer:**

Investigate the specific source/input/configuration producing that sourcetype.

---

## 115. Events exist but searches return zero results.

**Answer:**

Check:

```text
Time range
Index
Sourcetype
Host
Field values
Timestamp
Search syntax
```

---

## 116. Search works with `index=*` but not `index=windows`.

What does that suggest?

**Answer:**

It may indicate that the events are stored in a different index than expected.

I'd identify the actual index and then correct the search or data-routing configuration.

---

## 117. Search works without sourcetype but fails when sourcetype is specified.

**Answer:**

The sourcetype may be incorrect, inconsistent, or the events may have been assigned a different sourcetype.

---

## 118. Search works by `_raw` but not by `src_ip`.

What does that suggest?

**Answer:**

The IP exists in the raw event but the field extraction isn't working as expected.

---

## 119. Search works on yesterday's data but not today's.

What do you investigate?

**Answer:**

Potential:

```text
Source format change
Configuration change
Field extraction change
Forwarder issue
Index routing
Deployment change
Timestamp problem
```

---

## 120. Alert stopped triggering after a vendor upgrade.

What do you do?

**Answer:**

Compare before/after event structure.

Check:

```text
Sourcetype
Fields
Values
Raw format
Parsing
CIM
Detection assumptions
```

Then test the detection against both old and new data.

---

# SECTION G — DATA QUALITY SCENARIOS

## 121. Your firewall suddenly sends 10x more logs.

What do you do?

**Answer:**

First identify whether this is:

```text
Real traffic increase
Configuration change
Logging-level change
Attack
Duplicate logging
Parsing problem
```

Then identify the source causing the increase.

---

## 122. You see duplicate authentication events.

**Answer:**

Investigate whether:

- Multiple collectors are forwarding the same data
    
- Inputs overlap
    
- Events are being retransmitted
    
- Data is being duplicated upstream
    

---

## 123. You see events with future timestamps.

**Answer:**

Check:

```text
Endpoint clock
NTP
Timezone
Timestamp extraction
Source formatting
```

---

## 124. Events have timestamps several hours behind.

**Answer:**

Investigate timezone configuration and source clock synchronization.

---

## 125. Why is NTP important in SOC?

**Answer:**

Accurate time synchronization allows reliable correlation and incident timelines across systems.

---

# SECTION H — REAL INTERVIEW SCENARIOS

## 126. Interviewer: "A firewall is sending logs, but no useful fields are extracted. What do you do?"

### Model answer

> "First I'd verify that the raw event contains the information I need. Then I'd confirm the sourcetype and parsing configuration. If the data exists in `_raw` but fields aren't extracted, I'd investigate field extraction or the appropriate vendor add-on. I'd then validate fields such as source IP, destination IP, port, action and protocol and test existing detections."

---

## 127. Interviewer: "Windows logs are visible, but your 4625 search doesn't return anything."

### Answer

I would verify:

```text
Index
Sourcetype
EventCode field
Actual Windows event
Time range
```

Then search more broadly to determine how the event is represented.

---

## 128. Interviewer: "You have data, but the fields don't match your detection."

### Answer

> "I'd determine whether the problem is field extraction or normalization. If multiple vendors are involved, I'd consider whether the data should be mapped to CIM fields rather than modifying every detection individually."

---

## 129. Interviewer: "You onboarded a new firewall. How do you prove it works?"

### Answer

I would validate:

```text
Events arriving
Correct index
Correct sourcetype
Correct timestamps
Expected fields
Expected event volume
CIM mapping if applicable
Searchability
Existing detection compatibility
```

---

## 130. "How do you know your data source is healthy?"

### Answer

I'd monitor:

```text
Event volume
Last-seen timestamp
Host count
Source count
Parsing quality
Expected fields
Ingestion latency
```

---

# SECTION I — SECURITY DATA PIPELINE

## 131. Explain a Windows login event reaching Splunk.

### Answer

```text
Windows generates 4624
       ↓
Collection mechanism
       ↓
Forwarder / collector
       ↓
Splunk receiving layer
       ↓
Indexer
       ↓
Index
       ↓
Search Head
       ↓
SPL
       ↓
Detection
       ↓
SOC Analyst
```

---

## 132. Where can failure occur?

Anywhere:

```text
Endpoint
Collection
Network
Forwarder
Receiver
Indexer
Parsing
Indexing
Search
Detection
```

---

## 133. Why is this model important?

**Answer:**

Because when data disappears, I can troubleshoot systematically instead of randomly changing Splunk searches.

---

## 134. What is ingestion latency?

**Answer:**

The delay between an event occurring and becoming available for search.

---

## 135. Why does ingestion latency matter for SOC?

**Answer:**

High latency can delay detection and response.

---

## 136. Scenario: A critical alert appears 30 minutes late.

What do you investigate?

**Answer:**

```text
Event timestamp
Ingestion timestamp
Forwarder
Network
Indexer
Queueing
Data volume
Parsing
Search scheduling
```

---

## 137. What is a data gap?

**Answer:**

A period during which expected telemetry is missing or incomplete.

---

## 138. Why are data gaps dangerous?

**Answer:**

They can create blind spots where attacker activity cannot be reliably detected or reconstructed.

---

## 139. How would you communicate a telemetry limitation?

### Strong answer:

> "The available telemetry does not provide enough evidence to determine whether the activity occurred during that period. I would document the limitation, identify alternative data sources, and avoid making a definitive conclusion beyond the available evidence."

---

## 140. Can a detection be perfect if telemetry is incomplete?

**Answer:**

No.

Detection quality depends heavily on telemetry availability, correctness, and coverage.

---

# SECTION J — ARCHITECTURE INTERVIEW CHALLENGES

## 141. Why not install every Splunk component on one machine?

**Answer:**

Small environments can use simpler architectures, but larger environments separate roles for scalability, performance, availability, and operational management.

---

## 142. Why separate indexers and search heads?

**Answer:**

It separates storage/indexing workloads from search coordination and improves scalability.

---

## 143. Why use forwarders instead of sending everything directly?

**Answer:**

Forwarders provide controlled collection, routing, buffering and centralized forwarding capabilities depending on deployment.

---

## 144. What happens if the network between forwarder and indexer fails?

**Answer:**

Depending on configuration, forwarding mechanisms may buffer data temporarily; prolonged failure can eventually result in data loss if buffers/storage limits are exceeded.

---

## 145. What is a queue?

**Answer:**

A queue is a buffer used during stages of data processing/forwarding.

---

## 146. Why monitor queues?

**Answer:**

Queue buildup can indicate processing bottlenecks, connectivity issues, or excessive data volume.

---

## 147. What happens during a sudden log storm?

**Answer:**

Data volume can overwhelm collection, forwarding, indexing, or search resources.

I'd identify the source and determine whether the spike is legitimate, malicious, duplicated, or caused by configuration.

---

## 148. How would a SOC analyst recognize an ingestion problem?

**Answer:**

Indicators include:

```text
Expected host missing
Event volume drop
Last-seen timestamp old
Detection suddenly stops
Search results decrease unexpectedly
```

---

## 149. What is the difference between missing data and missing fields?

**Answer:**

**Missing data:** Events aren't arriving.

**Missing fields:** Events arrive, but required information isn't parsed/extracted.

---

## 150. Give me the complete troubleshooting methodology.

### ⭐ Model answer

> "I start by confirming whether the source is generating the expected logs. Then I trace the data path through collection, forwarding, network connectivity, receiving, indexing and search. If events exist, I inspect `_raw`, timestamps, sourcetype and field extraction. If the data is present but detections don't work, I check normalized fields and detection assumptions. I document the root cause and validate the fix with known test events."

---

# 🔥 PART 2 — MASTER REVISION

You should now understand this:

```text
                 DATA SOURCE
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
      Windows      Firewall       DNS
        │            │            │
        └────────────┼────────────┘
                     ▼
             COLLECTION LAYER
                     │
                     ▼
                 FORWARDER
                     │
                     ▼
                  NETWORK
                     │
                     ▼
                 INDEXER
                     │
               ┌─────┴─────┐
               ▼           ▼
             INDEX       PARSING
               │           │
               └─────┬─────┘
                     ▼
              FIELD EXTRACTION
                     │
                     ▼
                   CIM
                     │
                     ▼
               DATA MODELS
                     │
                     ▼
                SEARCH HEAD
                     │
                     ▼
                   SPL
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       SEARCH     DETECTION   DASHBOARD
          │          │
          └────┬─────┘
               ▼
             ALERT
               │
               ▼
          SOC ANALYST
               │
               ▼
          INVESTIGATION
```

## The most important distinction

When troubleshooting Splunk, always ask:

### **Is the data missing?**

or

### **Is the data present but unusable?**

That gives you two completely different investigation paths.

```text
DATA MISSING
     ↓
Collection
Forwarder
Network
Indexer
Input
Configuration

DATA PRESENT
     ↓
Timestamp
Sourcetype
Parsing
Field extraction
CIM
Detection logic
```

---

# ⭐ 10 Questions You Should Practice Out Loud

1. **Explain Splunk architecture end-to-end.**
    
2. **Explain how Windows logs reach Splunk.**
    
3. **What happens when logs stop arriving?**
    
4. **How do you troubleshoot missing fields?**
    
5. **What is the difference between index, source and sourcetype?**
    
6. **What is CIM and why does a SOC care?**
    
7. **What would you do if a detection suddenly stopped working?**
    
8. **How would you onboard a firewall?**
    
9. **How would you prove a data source is healthy?**
    
10. **How do you distinguish an ingestion problem from a parsing problem?**
    
---
# SECTION A — SPL FUNDAMENTALS

## 151. What is the basic structure of an SPL search?

**Answer:**

```spl
index=windows EventCode=4625
| stats count by user
| sort - count
```

Think:

```text
Search/filter
     ↓
Transform
     ↓
Analyze
     ↓
Present
```

---

## 152. What does the pipe `|` mean?

**Answer:**

It passes the output of one SPL command to the next.

```spl
index=windows
| stats count by user
```

The `stats` command receives the events returned by the initial search.

---

## 153. What is the difference between a base search and a transforming command?

**Answer:**

A base search retrieves relevant events.

A transforming command changes or aggregates the results.

Example:

```spl
index=windows EventCode=4625
```

retrieves events.

```spl
| stats count by user
```

aggregates them.

---

## 154. How do you search a specific index?

```spl
index=windows
```

---

## 155. How do you search a specific host?

```spl
index=windows host=DC01
```

---

## 156. How do you search a specific sourcetype?

```spl
index=windows sourcetype=WinEventLog:Security
```

---

## 157. How do you search for a specific user?

```spl
index=windows user="administrator"
```

---

## 158. How do you search for a specific IP?

```spl
index=network src_ip="10.10.10.25"
```

---

## 159. How do you specify the time range?

```spl
index=windows earliest=-24h latest=now
```

---

## 160. Why should you specify a time range?

**Answer:**

It reduces the amount of data searched and makes the investigation more focused and efficient.

---

# SPL INTERVIEW MASTER PREPARATION

## Section 1 — Search Logic & Filtering

|SPL Concept|Description|Example|
|---|---|---|
|`AND`|Requires multiple conditions to match.|`index=windows user=admin action=failure`|
|`OR`|Matches either condition.|`index=windows (user=admin OR user=root)`|
|`NOT`|Excludes matching events.|`index=windows NOT user=administrator`|
|Multiple Event IDs|Searches for multiple event IDs.|`index=windows (EventCode=4624 OR EventCode=4625)`|
|Multiple Users|Searches for multiple users.|`index=windows (user=alice OR user=bob)`|
|Wildcard `*`|Matches variable characters according to Splunk search semantics.|`user=admin*`|
|Phrase Search|Searches for a phrase.|`"failed password"`|
|`search`|Filters events using Splunk search syntax.|`index=windows action=failure`|
|`where`|Filters results using field expressions.|`\| where count > 10`|
|`where` with `eval`|Filters using a calculated field.|`\| eval ratio=failed/success \| where ratio > 10`|
|`index`|Restricts the search to a specific data source/index.|`index=windows`|
|Time Range|Limits the amount of data searched.|`earliest=-24h latest=now`|

---

# Section 2 — Fields & Basic SPL Commands

|SPL Concept|Description|Example|
|---|---|---|
|Field|A structured attribute of an event.|`user=admin`|
|`_raw`|Contains the original raw event.|`\| search "Failed password"`|
|`_time`|Contains the event timestamp.|`\| sort - _time`|
|`table`|Displays selected fields.|`\| table _time user src_ip action`|
|`sort`|Sorts results.|`\| sort - count`|
|`head`|Returns the first N results.|`\| head 10`|
|`tail`|Returns the last N results.|`\| tail 10`|
|`dedup`|Removes duplicate results based on specified fields.|`\| dedup user`|
|`as`|Renames an output field.|`\| stats count as failures`|
|`by`|Defines grouping fields.|`\| stats count by user`|
|`Aliases`|Provides alternative/normalized field names.|`src_ip` → `source_ip`|

---

# Section 3 — `stats` & Aggregation

This is one of the **most important interview sections**.

|SPL Concept|Description|Example|
|---|---|---|
|`stats`|Aggregates events into statistical results.|`\| stats count by user`|
|`count`|Counts events.|`\| stats count`|
|`count by user`|Counts events for each user.|`\| stats count by user`|
|`count by src_ip`|Counts events for each source IP.|`\| stats count by src_ip`|
|Multiple grouping fields|Groups by multiple fields.|`\| stats count by user src_ip`|
|`dc()`|Calculates distinct count.|`\| stats dc(src_ip) as unique_ips by user`|
|`values()`|Returns distinct values.|`\| stats values(src_ip) by user`|
|`sum()`|Calculates a total.|`\| stats sum(bytes_out) by src_ip`|
|`avg()`|Calculates an average.|`\| stats avg(bytes_out) by src_ip`|
|`min()`|Returns the minimum value.|`\| stats min(bytes_out) by host`|
|`max()`|Returns the maximum value.|`\| stats max(bytes_out) by host`|
|`stats` + `sort`|Finds highest/lowest values.|`\| stats count by src_ip \| sort - count`|
|`stats` + `where`|Filters aggregated results.|`\| stats count by user \| where count > 50`|
|`stats` + `head`|Finds top/bottom results.|`\| stats count by src_ip \| sort - count \| head 10`|

### Core interview pattern

```spl
index=windows EventCode=4625
| stats count by user
| sort - count
```

**Think:**  
`Search → Aggregate → Sort → Prioritize`

---

# Section 4 — `eval` & Conditional Logic

|SPL Concept|Description|Example|
|---|---|---|
|`eval`|Creates or modifies fields.|`\| eval MB=bytes/1024/1024`|
|`if()`|Performs a simple true/false condition.|`\| eval risk=if(count>20,"High","Normal")`|
|`case()`|Creates multiple conditional categories.|`\| eval severity=case(count>100,"High",count>50,"Medium",true(),"Low")`|
|Calculated Field|Creates a field from existing values.|`\| eval ratio=failed/success`|
|Risk Score|Creates a derived risk score.|`\| eval risk=failed_logins*2`|
|Suspicious Flag|Creates a yes/no classification.|`\| eval suspicious=if(count>100,"YES","NO")`|
|String Manipulation|Modifies string fields using supported functions.|`\| eval username=lower(user)`|
|`eval` + `where`|Calculates then filters.|`\| eval risk=failed*2 \| where risk>50`|

---

# Section 5 — `table`, `sort`, `dedup`, `head`, `tail`

|SPL Concept|Description|Example|
|---|---|---|
|`table`|Selects fields for final presentation.|`\| table _time user src_ip action`|
|`sort`|Orders results.|`\| sort - count`|
|`head`|Keeps first N results.|`\| head 20`|
|`tail`|Keeps last N results.|`\| tail 20`|
|`dedup`|Removes duplicate results.|`\| dedup user`|
|`sort` + `head`|Finds top results.|`\| sort - count \| head 10`|
|`table` at end|Keeps final output clean.|`\| table _time user src_ip`|
|`table` too early|Can remove fields required later.|`\| table user src_ip \| stats count by user`|
|`dedup` caution|May remove useful evidence.|`\| dedup src_ip`|
|Sort caution|Sorting large datasets can be expensive.|`\| sort - bytes_out`|

---

# Section 6 — Time Analysis

|SPL Concept|Description|Example|
|---|---|---|
|`timechart`|Aggregates events into time-based buckets.|`\| timechart span=5m count`|
|`span`|Defines bucket size.|`span=15m`|
|`bin`|Buckets values or time.|`\| bin _time span=5m`|
|Time Trend|Shows activity over time.|`\| timechart span=1h count`|
|Login Spike|Detects authentication spikes.|`index=windows EventCode=4625 \| timechart span=5m count`|
|Activity by User|Shows activity for each user over time.|`\| timechart span=15m count by user`|
|Baseline|Represents normal activity.|Historical activity used for comparison.|
|Anomaly|Activity that deviates from an established baseline.|Unusual login volume compared with normal behavior.|

---

# Section 7 — `rex` & Field Extraction

|SPL Concept|Description|Example|
|---|---|---|
|`rex`|Extracts or transforms fields using regex.|`\| rex "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"`|
|Named Capture Group|Creates a field from a regex match.|`(?<src_ip>...)`|
|Extract IP|Extracts an IP from raw data.|`\| rex "client=(?<src_ip>\d+\.\d+\.\d+\.\d+)"`|
|Extract Username|Extracts username from raw data.|`\| rex "user=(?<username>\S+)"`|
|`rex` Use Case|Useful when required information isn't already parsed.|Extract `src_ip` from `_raw`.|
|`rex` Caution|Avoid unnecessary runtime regex when fields already exist.|Use `src_ip` directly if already extracted.|
|Regex Validation|Ensures the pattern correctly matches actual events.|Test against representative `_raw` data.|

---

# Section 8 — Lookups & Enrichment

|SPL Concept|Description|Example|
|---|---|---|
|`lookup`|Enriches events with external/static data.|`\| lookup asset_lookup host OUTPUT owner,criticality`|
|Enrichment|Adds useful context to an event.|Asset owner, department, criticality.|
|Threat Intelligence Lookup|Adds reputation/intelligence information.|`\| lookup threat_intel src_ip OUTPUT threat_type`|
|Asset Lookup|Adds asset information.|`\| lookup asset_lookup host OUTPUT owner,criticality`|
|User Lookup|Adds identity information.|`\| lookup user_lookup user OUTPUT department,role`|
|Lookup Validation|Ensures lookup information is accurate/current.|Verify asset ownership before relying on it.|
|Lookup Risk|Incorrect enrichment can lead to wrong prioritization.|Stale asset owner information.|

---

# Section 9 — `eventstats` & `streamstats`

|SPL Concept|Description|Example|
|---|---|---|
|`eventstats`|Adds aggregate statistics while retaining individual events.|`\| eventstats count as user_failures by user`|
|`stats` vs `eventstats`|`stats` produces aggregated results; `eventstats` preserves events.|`\| eventstats count as total_failures by user`|
|Event-level Context|Adds group-level information to individual events.|`\| eventstats avg(bytes) as avg_bytes by user`|
|`streamstats`|Calculates running/sequential statistics.|`\| streamstats count as sequence by user`|
|`eventstats` vs `streamstats`|`eventstats` gives group statistics; `streamstats` gives running statistics.|`eventstats count` vs `streamstats count`|
|Sequence Analysis|Useful for analyzing repeated or ordered behavior.|`\| sort 0 _time \| streamstats count by user`|

### Easy interview memory

```text
stats
   ↓
Aggregate and reduce events

eventstats
   ↓
Aggregate but KEEP events

streamstats
   ↓
Running / sequential calculation
```

---

# Section 10 — `transaction`, `join`, Subsearches

|SPL Concept|Description|Example|
|---|---|---|
|`transaction`|Groups related events into transactions.|`\| transaction session_id`|
|`transaction` Use Case|Useful when events naturally belong to the same transaction/session.|`\| transaction user maxspan=30m`|
|`transaction` Risk|Can be expensive on large datasets.|Prefer `stats` where appropriate.|
|`join`|Combines datasets using a common field.|`\| join user [search index=auth]`|
|`join` Risk|Can be resource-intensive and scale poorly.|Consider `lookup` or `stats`.|
|Subsearch|A search nested inside another search.|`index=network [ search index=threat_ip \| fields src_ip ]`|
|Subsearch Risk|Can introduce performance and complexity issues.|Avoid unnecessary subsearches.|
|Alternatives|Other approaches may be more efficient.|`stats`, `eventstats`, `lookup`, `append`, `multisearch`|

---

# Section 11 — Windows Security SPL

|Security Concept|Description|Example|
|---|---|---|
|Successful Logon|Searches successful Windows authentication.|`index=windows EventCode=4624`|
|Failed Logon|Searches failed authentication.|`index=windows EventCode=4625`|
|Process Creation|Searches process creation activity.|`index=windows EventCode=4688`|
|Explicit Credentials|Searches explicit credential usage.|`index=windows EventCode=4648`|
|Privileged Logon|Searches special privilege assignments/logons.|`index=windows EventCode=4672`|
|Account Creation|Searches newly created accounts.|`index=windows EventCode=4720`|
|Group Membership|Searches security group membership changes.|`index=windows (EventCode=4728 OR EventCode=4732)`|
|Account Lockout|Searches account lockout events.|`index=windows EventCode=4740`|
|Scheduled Task|Searches scheduled task creation.|`index=windows EventCode=4698`|

---

# Section 12 — PowerShell Investigation

|SPL Concept|Description|Example|
|---|---|---|
|PowerShell Activity|Searches PowerShell process execution.|`index=windows process_name="powershell.exe"`|
|Encoded PowerShell|Searches for encoded PowerShell commands.|`index=windows command_line="*-EncodedCommand*"`|
|Office → PowerShell|Looks for Office applications launching PowerShell.|`parent_process_name="WINWORD.EXE" process_name="powershell.exe"`|
|PowerShell Investigation|Examines user, host, parent process, command line, network, and child processes.|Correlate process + network + EDR telemetry.|
|Encoded Command Caution|Encoding can obscure commands but isn't proof of malicious activity.|Decode and inspect the actual command.|

---

# Section 13 — DNS Investigation

|SPL Concept|Description|Example|
|---|---|---|
|Top Queried Domains|Finds frequently queried domains.|`index=dns \| stats count by query \| sort - count \| head 50`|
|DNS Volume|Shows DNS activity by source.|`\| stats count by src_ip`|
|NXDOMAIN|Finds failed DNS resolutions.|`index=dns response_code=NXDOMAIN \| stats count by src_ip`|
|DNS Anomaly|Identifies unusual DNS behavior.|Compare query volume against baseline.|
|DNS Tunneling|Investigates suspicious DNS-based data transfer.|Examine query length, frequency, entropy, reputation, and host behavior.|
|DGA Investigation|Investigates possible algorithmically generated domains.|Examine unusual domain patterns + DNS volume + endpoint activity.|

---

# Section 14 — Firewall & Network Investigation

|SPL Concept|Description|Example|
|---|---|---|
|Blocked Traffic|Searches denied connections.|`index=firewall action=blocked`|
|Top Blocked IPs|Finds source IPs generating the most blocked traffic.|`\| stats count by src_ip \| sort - count`|
|Allowed Traffic|Searches permitted connections.|`index=firewall action=allowed`|
|Destination Ports|Shows ports contacted by a host.|`\| stats count by dest_port`|
|Outbound Traffic|Finds high-volume outbound communication.|`\| stats sum(bytes_out) as outbound by src_ip`|
|Destination Analysis|Finds hosts contacting many destinations.|`\| stats dc(dest_ip) as destinations by src_ip`|
|Port Scanning|Looks for one source contacting many ports.|`\| stats dc(dest_port) as ports by src_ip`|
|Network Baseline|Establishes normal network behavior.|Compare current destination/port volume with historical behavior.|

---

# Section 15 — SOC Detection Scenarios

|Detection Scenario|Description|Example|
|---|---|---|
|Failed Login Threshold|Finds users exceeding a failed-login threshold.|`index=windows EventCode=4625 \| stats count as failures by user \| where failures > 50`|
|Failed Login by IP|Finds source IPs generating many failures.|`index=windows EventCode=4625 \| stats count as failures by src_ip \| where failures > 50`|
|Password Spraying|Looks for one IP attacking many accounts.|`\| stats dc(user) as users count as failures by src_ip \| where users > 10 AND failures > 30`|
|Multiple IPs per User|Finds users authenticating from many source IPs.|`\| stats dc(src_ip) as unique_sources by user \| where unique_sources > 5`|
|Many Destinations|Finds hosts contacting many destinations.|`\| stats dc(dest_ip) as destinations by src_ip \| where destinations > 100`|
|Many Ports|Finds hosts contacting many destination ports.|`\| stats dc(dest_port) as ports by src_ip \| where ports > 50`|
|High Outbound Traffic|Finds hosts generating unusually high outbound traffic.|`\| stats sum(bytes_out) as outbound by src_ip \| sort - outbound`|
|DNS Anomaly|Finds unusual DNS activity.|`index=dns \| stats count by src_ip \| sort - count`|

---

# Section 16 — Investigation Methodology

This is where your **SOC Analyst L2/Senior SOC Analyst** preparation becomes much stronger.

|Investigation Concept|Description|Example|
|---|---|---|
|Start with the Question|Define what you are actually trying to determine.|"Was this account compromised?"|
|Identify the Data|Determine which logs can answer the question.|Windows Security + EDR + DNS + firewall.|
|Narrow the Scope|Use index, time, host, user, or IP to reduce noise.|`index=windows user=alice earliest=-24h`|
|Search|Find relevant events.|`EventCode=4625`|
|Aggregate|Identify patterns.|`\| stats count by src_ip,user`|
|Enrich|Add contextual information.|Asset/user/threat-intelligence lookup.|
|Correlate|Connect related events across telemetry.|Failed login → success → process → network.|
|Validate|Verify that the evidence actually supports the hypothesis.|Check raw events and surrounding activity.|
|Challenge Assumptions|Consider legitimate explanations.|VPN, scanner, administrator, application failure.|
|Determine Impact|Identify affected accounts, hosts, or systems.|Compromised endpoint + privileged account.|
|Document|Record evidence, timeline, findings, and actions.|SOC incident report.|

---

# Section 17 — Full Attack Investigation Flow

|Investigation Stage|What You Look For|Typical SPL|
|---|---|---|
|Authentication|Failed/successful logons|`EventCode=4624 OR EventCode=4625`|
|Source|Originating IP/device|`\| stats count by src_ip`|
|Account|Targeted user|`\| stats count by user`|
|Privilege|Privileged activity|`EventCode=4672`|
|Process|Process execution|`EventCode=4688`|
|PowerShell|Suspicious scripting|`process_name="powershell.exe"`|
|DNS|Domain resolution|`index=dns`|
|Network|External/internal communication|`index=firewall`|
|Persistence|Scheduled tasks/accounts/services|`EventCode=4698` / account events|
|Lateral Movement|Authentication across hosts|`EventCode=4624` + source/destination context|
|Impact|Affected systems/accounts|Correlate all evidence|
|Conclusion|Determine what the evidence supports|Timeline + evidence + validation|

---

# Section 18 — SPL Performance & Troubleshooting

|Concept|Description|Example|
|---|---|---|
|Specify Index|Limits search scope.|`index=windows`|
|Narrow Time Range|Reduces data volume.|`earliest=-24h latest=now`|
|Avoid Unnecessary `sort`|Sorting can be expensive.|Prefer aggregation before sorting.|
|Avoid Unnecessary `transaction`|Can be expensive at scale.|Use `stats` where appropriate.|
|Avoid Unnecessary `join`|Can have scalability limitations.|Consider `lookup` or `stats`.|
|Avoid Early `table`|May remove fields required later.|Put `table` near the end.|
|Validate Fields|Confirm fields actually exist.|Check `src_ip`, `user`, `EventCode`.|
|Inspect `_raw`|Verify actual event content.|`\| table _time _raw`|
|Check Sourcetype|Confirm correct data parsing.|`sourcetype=WinEventLog:Security`|
|Check Time|Incorrect timestamps can hide evidence.|Compare `_time` with raw event time.|
|Check Data Availability|Verify the expected events actually exist.|Search a broad time range first.|
|Validate SPL|Ensure the query answers the intended security question.|Compare results with known events.|

---

# Section 19 — Senior SOC Interview Questions

|Interview Concept|Strong Answer|
|---|---|
|Biggest SPL mistake|Writing technically valid SPL that does not answer the actual security question.|
|Biggest investigation mistake|Treating a single indicator as proof of compromise without supporting evidence.|
|Biggest detection mistake|Ignoring false positives, baselines, and operational context.|
|Biggest troubleshooting mistake|Assuming the SPL is wrong before verifying that the expected data exists.|
|Why use `stats`?|To efficiently aggregate large event sets and identify patterns.|
|Why use `eventstats`?|To add aggregate context while preserving individual events.|
|Why use `streamstats`?|To perform sequential/running analysis.|
|Why use `rex`?|To extract fields from raw data when proper field extraction isn't available.|
|Why use `lookup`?|To enrich events with useful contextual information.|
|Why use `timechart`?|To identify trends, spikes, and changes over time.|
|Why narrow the time range?|To improve performance and keep the investigation focused.|
|Why specify the index?|To reduce search scope and improve efficiency.|
|Why normalize fields?|To make detections consistent across different data sources.|
|What makes a good Splunk analyst?|Understands the data, asks the right security question, writes efficient SPL, correlates evidence, validates assumptions, and produces an actionable conclusion.|

---

# The preparation order I recommend

Don't memorize all 190+ questions randomly. Study them in this order:

```text
1. Search Logic
       ↓
2. Fields & Basic Commands
       ↓
3. stats
       ↓
4. eval
       ↓
5. table / sort / dedup / head
       ↓
6. timechart / bin / span
       ↓
7. rex
       ↓
8. lookup / enrichment
       ↓
9. eventstats
       ↓
10. streamstats
       ↓
11. transaction / join / subsearch
       ↓
12. Windows Security
       ↓
13. PowerShell
       ↓
14. DNS
       ↓
15. Firewall / Network
       ↓
16. Detection Scenarios
       ↓
17. Investigation Methodology
       ↓
18. Performance / Troubleshooting
       ↓
19. Senior SOC Interview Questions
```

### Most important commands to master first

If you're preparing specifically for a **SOC Analyst L2 / Senior SOC Analyst interview**, I'd put these at the top of your practical priority list:

```text
stats
eval
where
search
rex
lookup
eventstats
streamstats
timechart
bin
sort
dedup
table
dc()
values()
count
sum()
avg()
min()
max()
```

And the **five mental models** to remember are:

```text
search  → Find the evidence

stats   → Summarize the evidence

eval    → Create meaning from the evidence

lookup  → Add context

correlate → Build the attack story
```
---

# 🔥 PART 3 — THE INTERVIEWER CHALLENGE

The interviewer may now give you:

> **"Here's a Splunk alert. You have 15 minutes. Investigate it."**

Your response should be:

```text
                 ALERT
                   ↓
              VALIDATE
                   ↓
          IDENTIFY ENTITIES
                   ↓
          DEFINE TIME WINDOW
                   ↓
             BASE SEARCH
                   ↓
              AGGREGATE
                   ↓
              FIND PATTERN
                   ↓
               PIVOT
          ┌────────┼────────┐
          ↓        ↓        ↓
       AUTH       EDR      DNS
          ↓        ↓        ↓
          └────────┼────────┘
                   ↓
                TIMELINE
                   ↓
              SCOPE / IMPACT
                   ↓
          BENIGN OR MALICIOUS?
             /             \
          BENIGN          MALICIOUS
             ↓               ↓
          CLOSE          ESCALATE
                             ↓
                       RESPONSE PLAYBOOK
```

### And when they ask:

**"What would you search next?"**

Don't say:

> "I would check Splunk."

Say specifically:

> "The alert shows a suspicious source IP. My next pivot would be that IP across authentication, DNS, firewall, proxy, and endpoint telemetry. If I find a successful authentication, I'd pivot to the user and host and investigate process execution immediately after the login."

That is the difference between **knowing Splunk** and **being able to work a SOC investigation**.

---

# SECTION A — WINDOWS SECURITY BASICS

## 351. What Windows logs are most important for a SOC analyst?

**Answer:**

The main ones are:

|Log|Why it matters|
|---|---|
|Security|Authentication, accounts, privileges|
|System|Services, drivers, system events|
|Application|Application activity/errors|
|PowerShell|Script activity|
|Sysmon|Detailed endpoint telemetry|
|Defender/EDR|Malware/process/network detections|

---

## 352. What is Windows Security Event Log?

**Answer:**

It records security-related activity such as:

- Logons
    
- Failed authentication
    
- Account creation
    
- Group changes
    
- Privileged activity
    
- Process creation, if configured
    
- Policy changes
    

---

| Event ID / Concept                                  | Description                                                                                                                                                                     | Example SPL                                                 |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **4624 — Successful Logon**                         | Indicates that a logon was successfully completed. Useful for investigating account access and correlating successful authentication after failed attempts.                     | `index=windows EventCode=4624`                              |
| **4625 — Failed Logon**                             | Indicates that a logon attempt failed. Useful for investigating brute force, password spraying, invalid credentials, and suspicious authentication activity.                    | `index=windows EventCode=4625`                              |
| **4634 — Logoff**                                   | Indicates that a logon session was terminated. Useful for building authentication timelines.                                                                                    | `index=windows EventCode=4634`                              |
| **4647 — User-Initiated Logoff**                    | Indicates that a user initiated the logoff operation.                                                                                                                           | `index=windows EventCode=4647`                              |
| **4648 — Explicit Credential Use**                  | Indicates that a process attempted to use explicit credentials rather than the credentials of the current logged-on user. Useful when investigating alternate credential usage. | `index=windows EventCode=4648`                              |
| **4672 — Special Privileges Assigned to New Logon** | Indicates that special/privileged rights were assigned to a newly created logon session. Useful for identifying privileged sessions.                                            | `index=windows EventCode=4672`                              |
| **4672 — Investigation Context**                    | This event is not automatically malicious. Administrators, service accounts, and other legitimate privileged processes can generate it.                                         | `index=windows EventCode=4672 \| stats count by user, host` |
| **4688 — New Process Created**                      | Indicates that a new process was created. Highly valuable for endpoint investigations, especially when command-line logging is available.                                       | `index=windows EventCode=4688`                              |

### Important interview distinction

|Event|What it tells you|
|---|---|
|**4624**|Someone successfully logged on|
|**4625**|Someone failed to log on|
|**4634**|A logon session ended|
|**4647**|The user initiated the logoff|
|**4648**|Explicit/alternate credentials were used|
|**4672**|The new logon received special privileges|
|**4688**|A process was created|

### 🔥 SOC correlation example

Don't investigate these events in isolation. A stronger investigation might look like:

```text
4625
Failed Logon
   ↓
4624
Successful Logon
   ↓
4672
Privileged Session
   ↓
4688
Suspicious Process
   ↓
DNS / Network
   ↓
Potential Impact
```

Example SPL:

```spl
index=windows
(EventCode=4624 OR EventCode=4625 OR EventCode=4672 OR EventCode=4688)
user="admin"
| table _time EventCode user host src_ip process_name command_line
| sort _time
```

---

# SECTION B — AUTHENTICATION INVESTIGATION

## 361. How do you investigate failed logins?

Start with:

```spl
index=windows EventCode=4625
| stats count by user src_ip host
| sort - count
```

Then investigate:

```text
Source
↓
Target user
↓
Number of failures
↓
Authentication type
↓
Successful login?
↓
Post-login activity
```

---

## 362. How do you identify brute force?

Example:

```spl
index=windows EventCode=4625
| stats count as failures by src_ip,user
| where failures > 20
| sort - failures
```

The threshold must be environment-specific.

---

## 363. What is password spraying?

**Answer:**

Trying a small number of passwords against many accounts.

Typical pattern:

```text
One source
   ↓
Many users
   ↓
Few attempts per user
```

---

## 364. SPL for a password-spraying hypothesis?

```spl
index=windows EventCode=4625
| stats dc(user) as users count as failures by src_ip
| where users >= 10
| sort - users
```

---

## 365. How is password spraying different from brute force?

**Answer:**

|Brute force|Password spraying|
|---|---|
|Many passwords|Few passwords|
|Usually one/few accounts|Many accounts|
|High attempts against target|Distributed attempts|

---

## 366. What would you check after detecting password spraying?

**Answer:**

I'd check:

1. Successful logins
    
2. Target accounts
    
3. Source reputation
    
4. VPN/proxy
    
5. Authentication type
    
6. Geographic context
    
7. Endpoint activity
    
8. Privileged accounts
    
9. Lateral movement
    

---

## 367. Find successful logins after failed attempts.

```spl
index=windows (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) as failures
        count(eval(EventCode=4624)) as successes
        by user src_ip
| where failures > 10 AND successes > 0
```

---

## 368. Why is "failed + successful login" important?

**Answer:**

Because it may indicate that an attacker eventually obtained valid credentials.

But it still requires investigation.

---

## 369. Scenario: 100 failed logins followed by one successful login.

**What do you do?**

**Answer:**

I would treat it as high-priority suspicious activity and investigate:

```text
Source IP
↓
Target account
↓
Successful login time
↓
Target host
↓
Logon type
↓
Process creation
↓
Network activity
↓
Privilege use
↓
Lateral movement
```

---

## 370. What is a logon type?

**Answer:**

Windows uses logon types to describe how authentication occurred.

Examples include:

- Interactive
    
- Network
    
- Remote Interactive
    
- Service
    
- Batch
    

The exact interpretation depends on the event.

---

# SECTION C — KERBEROS & NTLM

## 371. What is Kerberos?

**Answer:**

A network authentication protocol widely used by Active Directory.

---

## 372. What is NTLM?

**Answer:**

A Windows authentication protocol based on challenge-response mechanisms.

---

## 373. Why should SOC analysts understand Kerberos?

**Answer:**

Because several AD attacks abuse Kerberos behavior.

Examples:

- Kerberoasting
    
- Pass-the-Ticket
    
- Ticket abuse
    
- Golden Ticket activity
    

---

## 374. What is Kerberoasting?

**Answer:**

An attack technique where an attacker requests service tickets for accounts associated with services and attempts offline password cracking against the ticket material.

MITRE ATT&CK: **T1558.003**

---

## 375. What telemetry could help detect Kerberoasting?

Look for unusual service-ticket request behavior, especially:

```text
User
↓
Service account
↓
Service principal
↓
Ticket requests
↓
Volume/baseline
```

Relevant Windows events can include **4769**, depending on audit configuration.

---

## 376. Example SPL for unusual ticket-request volume.

```spl
index=windows EventCode=4769
| stats count dc(ServiceName) as services by user
| sort - count
```

This is a **hunting starting point**, not a complete Kerberoasting detector.

---

## 377. Is every 4769 suspicious?

**Answer:**

No.

Kerberos service-ticket requests are normal AD behavior.

---

## 378. What is Pass-the-Ticket?

**Answer:**

Using a stolen Kerberos ticket to authenticate without obtaining the user's password directly.

MITRE ATT&CK: **T1550.003**

---

## 379. What is Pass-the-Hash?

**Answer:**

Using a stolen NTLM password hash to authenticate without knowing the plaintext password.

MITRE ATT&CK: **T1550.002**

---

## 380. What should you investigate if you suspect credential theft?

**Answer:**

I'd investigate:

```text
Credential access
↓
Account used
↓
Source host
↓
Target host
↓
Authentication type
↓
Privileged access
↓
Process activity
↓
Lateral movement
```

---

# SECTION D — ACTIVE DIRECTORY

## 381. What is Active Directory?

**Answer:**

Microsoft's directory service used to manage identities, computers, groups, policies and resources in Windows environments.

---

## 382. What is a Domain Controller?

**Answer:**

A Windows server responsible for domain authentication and directory services.

---

## 383. Why are Domain Controllers high-value assets?

**Answer:**

Compromise can provide attackers with significant control over domain identities and infrastructure.

---

## 384. What is Event ID 4720?

**Answer:**

A user account was created.

---

## 385. Why investigate account creation?

Because attackers may create accounts for persistence.

---

## 386. SPL:

```spl
index=windows EventCode=4720
| table _time host user SubjectUserName TargetUserName
```

Field names depend on your ingestion.

---

## 387. What is Event ID 4728?

**Answer:**

A member was added to a security-enabled global group.

---

## 388. What is Event ID 4732?

**Answer:**

A member was added to a security-enabled local group.

---

## 389. Why are group membership changes important?

Because attackers may add accounts to privileged groups.

---

## 390. Scenario: User added to Domain Admins.

**Answer:**

I would immediately investigate:

```text
Who performed change?
↓
Which account was added?
↓
Was it approved?
↓
Source workstation
↓
Authentication history
↓
Process activity
↓
Other changes
```

---

# SECTION E — PRIVILEGED ACCESS

## 391. What is privilege escalation?

**Answer:**

An attacker gains higher privileges than originally obtained.

Example:

```text
Standard User
     ↓
Local Admin
     ↓
SYSTEM
     ↓
Domain Admin
```

---

## 392. How can Windows privilege escalation be detected?

Look for:

- Suspicious process creation
    
- Service creation
    
- Scheduled tasks
    
- Token/privilege activity
    
- UAC bypass indicators
    
- Credential theft
    
- Unexpected administrative activity
    

---

## 393. What is Event ID 4672 useful for?

It can show privileged logon sessions receiving special privileges.

---

## 394. How do you investigate suspicious privileged logon?

```spl
index=windows EventCode=4672
| stats count by SubjectUserName host
| sort - count
```

Then pivot into 4624 and 4688.

---

## 395. Why correlate 4672 with 4624?

**Answer:**

4624 provides authentication context, while 4672 provides privilege assignment context.

Together they can help establish the privileged session.

---

## 396. Scenario: Normal user suddenly gets privileged activity.

**Answer:**

I would determine:

```text
Was elevation legitimate?
Who initiated it?
From which host?
What process ran?
What happened immediately afterward?
```

---

## 397. What is UAC?

**Answer:**

User Account Control is a Windows security feature designed to limit unauthorized elevation of privileges.

---

## 398. Is every UAC-related event malicious?

No.

Legitimate software and administrators can trigger elevation.

---

## 399. What is SYSTEM?

**Answer:**

A highly privileged Windows service account/context.

---

## 400. Why is SYSTEM execution significant?

Unexpected SYSTEM-level process execution can indicate successful privilege escalation or a legitimate system/service operation. Context is critical.

---

# SECTION F — PROCESS CREATION

## 401. Why is process creation important?

Because attackers must execute programs or commands during many attack stages.

---

## 402. What does Event ID 4688 show?

Process creation telemetry, subject to auditing/configuration.

---

## 403. Why is command-line logging valuable?

It can reveal the actual arguments used to execute a process.

---

## 404. What is Sysmon?

**Answer:**

Microsoft Sysinternals' system monitoring tool that can provide detailed endpoint telemetry.

---

## 405. Why do SOC teams deploy Sysmon?

To obtain richer telemetry for:

- Process creation
    
- Network connections
    
- File activity
    
- Registry activity
    
- Process relationships
    

depending on configuration.

---

## 406. What is parent-child process relationship?

Example:

```text
WINWORD.EXE
     ↓
powershell.exe
     ↓
cmd.exe
     ↓
payload.exe
```

This relationship can reveal suspicious execution chains.

---

## 407. Why is Office → PowerShell suspicious?

It can be associated with malicious document execution, although legitimate automation also exists.

---

## 408. Example hunt:

```spl
index=endpoint
parent_process_name IN ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE")
process_name="powershell.exe"
| table _time host user parent_process_name process_name command_line
```

---

## 409. What would you investigate next?

**Answer:**

The PowerShell command line, parent process, user, downloaded files, network connections, child processes and EDR detections.

---

## 410. What is LOLBin?

**Answer:**

A legitimate operating-system binary that attackers can abuse to perform malicious actions.

Examples include certain Windows utilities such as:

```text
mshta
rundll32
regsvr32
certutil
wmic
powershell
```

Detection should focus on **context and behavior**, not merely binary names.

---

# SECTION G — POWERSHELL

## 411. Why is PowerShell important to SOC analysts?

Because it is legitimate administrative tooling that is also frequently abused by attackers.

---

## 412. What is encoded PowerShell?

PowerShell commands can be supplied in encoded form.

A common indicator is:

```text
-EncodedCommand
```

---

## 413. SPL:

```spl
index=endpoint
| search command_line="*-EncodedCommand*"
```

---

## 414. Is encoded PowerShell automatically malicious?

**Answer:**

No.

Encoding can have legitimate uses.

---

## 415. What makes PowerShell more suspicious?

For example:

```text
Encoded command
+
Internet connection
+
Unusual parent process
+
Suspicious user
+
Payload download
```

The combination is much stronger than one indicator.

---

## 416. What is PowerShell Script Block Logging?

**Answer:**

A Windows PowerShell logging capability that can capture script block content when appropriately configured.

---

## 417. Why is it useful?

It can provide visibility into commands/scripts that may not be obvious from process names alone.

---

## 418. Scenario: PowerShell downloads an executable.

What do you investigate?

```text
PowerShell command
↓
URL/domain
↓
Downloaded file
↓
Hash
↓
File execution
↓
Parent/child process
↓
Network connections
↓
Persistence
```

---

## 419. How would you map this to MITRE?

Potentially:

- Command and Scripting Interpreter
    
- Ingress Tool Transfer
    
- Execution
    

Exact mapping depends on observed behavior.

---

## 420. Why shouldn't you create an alert for every PowerShell execution?

Because PowerShell is heavily used for legitimate administration and automation.

---

# SECTION H — PERSISTENCE

## 421. What is persistence?

**Answer:**

Techniques attackers use to maintain access after reboot, logout, credential changes, etc.

---

## 422. Common Windows persistence mechanisms?

Examples:

- Scheduled tasks
    
- Services
    
- Registry Run keys
    
- Startup folders
    
- WMI event subscriptions
    
- Accounts
    
- Group modifications
    

---

## 423. What is Event ID 4698?

Scheduled task created.

---

## 424. Why investigate scheduled tasks?

Attackers can use them for persistence or execution.

---

## 425. Example SPL:

```spl
index=windows EventCode=4698
| table _time host SubjectUserName TaskName
```

---

## 426. What is service-based persistence?

An attacker may create or modify a Windows service so malicious code executes through the service mechanism.

---

## 427. What should you investigate after detecting a suspicious service?

```text
Service name
↓
Binary path
↓
Account
↓
Creation/modification time
↓
Parent process
↓
File hash
↓
Network activity
```

---

## 428. What is Registry Run Key persistence?

Programs configured in specific Registry locations can execute when a user logs in.

---

## 429. Why is registry telemetry useful?

It can reveal configuration changes associated with persistence, defense evasion, and other activity.

---

## 430. What is WMI persistence?

**Answer:**

Abusing Windows Management Instrumentation mechanisms to trigger malicious execution based on events or other conditions.

---

# SECTION I — LATERAL MOVEMENT

## 431. What is lateral movement?

**Answer:**

Moving from one compromised system/account to other systems within the environment.

---

## 432. Common Windows lateral movement techniques?

Examples:

```text
RDP
SMB
WinRM
WMI
Remote services
PsExec-like activity
Valid accounts
```

---

## 433. What is RDP?

Remote Desktop Protocol.

---

## 434. What Event ID can indicate an RDP logon?

A common Windows event is **4624**, with the appropriate Remote Interactive logon type.

---

## 435. Example RDP investigation:

```spl
index=windows EventCode=4624
| search LogonType=10
| stats count by user src_ip host
```

Field names can differ depending on the TA/normalization.

---

## 436. Scenario: User normally works from one workstation but suddenly RDPs into five servers.

**Answer:**

I would investigate:

```text
Source workstation
↓
User
↓
Destination servers
↓
Authentication
↓
Process execution
↓
Privilege use
↓
File shares
↓
Network connections
```

---

## 437. What is SMB?

Server Message Block, commonly used for Windows file/resource sharing.

---

## 438. Why is SMB important during an attack?

It can be used for legitimate administration and file sharing, but attackers may abuse it for lateral movement and remote operations.

---

## 439. What is WinRM?

Windows Remote Management.

It can be used for legitimate remote administration and can also be abused for lateral movement.

---

## 440. Why is remote administration difficult to detect?

Because attackers may use legitimate administrative protocols and credentials.

---

# SECTION J — ATTACK WALKTHROUGH

## 441. Scenario: Phishing → Credential Theft → VPN → Internal Access

The interviewer asks:

> "Walk me through how you would investigate this in Splunk."

### Answer:

I'd build a timeline:

```text
PHISHING
   ↓
Credential submission
   ↓
VPN login
   ↓
Internal authentication
   ↓
Endpoint activity
   ↓
Lateral movement
```

Then search:

```spl
index=email
```

→ identify user and timestamp.

Then:

```spl
index=vpn user="victim"
```

→ investigate authentication.

Then:

```spl
index=windows user="victim"
```

→ identify internal access.

Then:

```spl
index=endpoint user="victim"
```

→ process execution.

Then:

```spl
index=network src_ip="..."
```

→ network activity.

---

## 442. Scenario: Brute Force → Successful Login → PowerShell

### Attack chain:

```text
4625
 ↓
4625
 ↓
4625
 ↓
4624
 ↓
4688
 ↓
PowerShell
```

### Investigation:

```spl
index=windows (EventCode=4624 OR EventCode=4625 OR EventCode=4688)
user="target"
| sort _time
| table _time EventCode user src_ip host process_name command_line
```

---

## 443. What makes this more suspicious?

Combination of:

```text
Repeated failures
+
Successful authentication
+
Unusual source
+
Privileged account
+
PowerShell
```

This is much stronger than any individual event.

---

## 444. Scenario: Attacker creates account after compromise.

Look for:

```spl
index=windows EventCode=4720
| table _time host SubjectUserName TargetUserName
```

Then correlate the creator with:

```text
4624
4672
4688
4728/4732
```

---

## 445. Scenario: Attacker creates account and adds it to privileged group.

Attack chain:

```text
4720
 ↓
4728/4732
 ↓
4624
 ↓
4672
 ↓
4688
```

### Interview answer:

> "I'd treat this as a potentially serious persistence and privilege escalation chain and establish who created the account, who modified the group, where the activity originated, whether the account authenticated, and what it did afterward."

---

# SECTION K — INCIDENT RESPONSE

## 446. When should an L1 analyst escalate?

**Answer:**

When evidence indicates likely compromise, significant impact, privileged-account compromise, active attack activity, or when the case exceeds the analyst's authorization/skill level.

---

## 447. Should an L1 analyst immediately disable the account?

**Answer:**

Not automatically.

Follow the organization's incident-response playbook and authorization.

---

## 448. What evidence should you document?

At minimum:

```text
Alert
Timestamp
User
Host
Source IP
Destination
Process
Command line
Authentication
Timeline
Indicators
MITRE technique
Scope
Impact
Actions
Conclusion
```

---

## 449. How do you explain your conclusion?

Use:

```text
What happened?
↓
How do I know?
↓
What evidence supports it?
↓
What is the scope?
↓
What is the impact?
↓
What action is required?
```

---

# 450. FINAL INTERVIEW SCENARIO

### Interviewer:

> **"You receive an alert saying a privileged account performed suspicious PowerShell activity from a workstation. Explain your entire investigation."**

### Strong L2 answer:

> "First, I would validate the alert and establish the exact timestamp, account, workstation and triggering PowerShell event. I would determine whether the privileged account activity is expected and identify the authentication that created the session."

Then:

```text
1. Validate alert
        ↓
2. Identify user/host
        ↓
3. Find authentication
        ↓
4. Check 4624 / 4672
        ↓
5. Find process creation
        ↓
6. Analyze PowerShell command line
        ↓
7. Check parent/child processes
        ↓
8. Check DNS/network activity
        ↓
9. Check downloaded/created files
        ↓
10. Check persistence
        ↓
11. Check lateral movement
        ↓
12. Establish scope
        ↓
13. Map MITRE ATT&CK
        ↓
14. Determine malicious/benign
        ↓
15. Follow IR playbook
        ↓
16. Document evidence
```

### Example investigation SPL:

```spl
index=windows
(
    EventCode=4624
    OR EventCode=4672
    OR EventCode=4688
)
user="admin"
earliest=-2h
latest=now
| sort 0 _time
| table _time EventCode host user src_ip process_name parent_process_name command_line
```

Then pivot to endpoint telemetry:

```spl
index=endpoint
user="admin"
host="WORKSTATION01"
earliest=-2h
latest=now
| sort 0 _time
| table _time process_name parent_process_name command_line dest_ip dest_port
```

Then network:

```spl
index=network
src_ip="10.10.10.25"
earliest=-2h
latest=now
| stats count sum(bytes_out) as bytes_out by dest_ip dest_port
| sort - bytes_out
```

### Final conclusion should sound like:

> **"I would not conclude compromise solely because a privileged account used PowerShell. I would correlate authentication, process ancestry, command-line activity, network connections, file activity, persistence and lateral movement. If the combined evidence supports malicious activity, I would escalate according to the incident-response playbook, preserve the relevant evidence and document the complete timeline and scope."**

---

# 🔥 What the interviewer is actually testing

By Q450, they aren't really asking:

> **"Do you know Splunk?"**

They're asking whether you can do this:

```text
SPL
 ↓
TELEMETRY
 ↓
SECURITY BEHAVIOR
 ↓
ATTACK TECHNIQUE
 ↓
TIMELINE
 ↓
SCOPE
 ↓
IMPACT
 ↓
DECISION
 ↓
RESPONSE
```

That's the **L2 mindset**.

---
# Splunk SOC Interview — Part 5

## Q451–550 — Network, Firewall, DNS, Proxy, VPN, IDS/IPS

### L1 → L2 | Scenario-Based | SPL | Attack Walkthroughs | Playbooks

This section is especially important for **network-focused SOC interviews**. The interviewer will often give you an IP, domain, firewall alert, VPN alert, or IDS finding and expect you to turn it into an investigation.

---

# SECTION A — NETWORK TELEMETRY

## 451. What network data sources are commonly onboarded into Splunk?

**Answer:**

- Firewalls
    
- IDS/IPS
    
- Proxy
    
- DNS
    
- VPN
    
- NetFlow
    
- Routers
    
- Switches
    
- Web gateways
    
- EDR/network telemetry
    
- Cloud network logs
    

---

## 452. What fields are important in network investigations?

Typical fields:

```text
src_ip
dest_ip
src_port
dest_port
protocol
action
bytes_in
bytes_out
hostname/domain
user
device
```

Exact names depend on the source/CIM.

---

## 453. What is the difference between source and destination IP?

**Answer:**

```text
src_ip  → initiator
dest_ip → target
```

But always verify the vendor's field semantics.

---

## 454. What is a firewall log?

**Answer:**

A record describing network traffic evaluated by a firewall.

It may include:

```text
Source
Destination
Port
Protocol
Action
Bytes
Rule
```

---

## 455. What does `action=blocked` mean?

**Answer:**

The firewall blocked the connection according to the relevant rule.

---

## 456. Does a blocked connection mean compromise?

**Answer:**

No.

It indicates attempted or policy-violating communication, not necessarily successful compromise.

---

## 457. Does `action=allowed` mean safe?

**Answer:**

No.

Allowed traffic can be completely legitimate or malicious.

---

## 458. Why are firewall logs useful?

Because they help establish:

```text
Who communicated?
With whom?
When?
On what port?
Was it allowed?
How much data?
```

---

## 459. Find blocked traffic.

```spl
index=firewall action=blocked
| stats count by src_ip dest_ip dest_port
| sort - count
```

---

## 460. Find the top blocked source IPs.

```spl
index=firewall action=blocked
| stats count by src_ip
| sort - count
| head 20
```

---

# SECTION B — PORT SCANNING

## 461. What is port scanning?

**Answer:**

An attacker or scanner probes ports to identify available services.

---

## 462. What is horizontal scanning?

One source scans the same port across many hosts.

```text
Attacker
 ↓
Host1:445
Host2:445
Host3:445
Host4:445
```

---

## 463. What is vertical scanning?

One source scans many ports on one host.

```text
Attacker
 ↓
Server
 ├─22
 ├─80
 ├─443
 ├─445
 └─3389
```

---

## 464. Detect many destinations from one source.

```spl
index=firewall
| stats dc(dest_ip) as destinations by src_ip
| where destinations > 50
| sort - destinations
```

---

## 465. Detect many ports against one destination.

```spl
index=firewall
| stats dc(dest_port) as ports by src_ip dest_ip
| where ports > 20
```

---

## 466. Is this enough to declare a port scan?

**Answer:**

No.

I'd check:

- Time window
    
- Connection rate
    
- Blocked/allowed ratio
    
- Scanner identity
    
- Asset role
    
- Vulnerability-management schedules
    
- Historical behavior
    

---

## 467. Scenario: Source scans 500 hosts.

**What do you do?**

**Answer:**

First determine whether the source is:

```text
Authorized scanner?
Security tool?
Admin workstation?
Compromised endpoint?
External IP?
```

Then determine whether the activity is successful and whether vulnerable services were discovered.

---

## 468. Why is an internal scanner different from an attacker?

Because vulnerability scanners legitimately perform broad probing.

---

## 469. How can you reduce false positives?

Use enrichment:

```spl
index=firewall
| lookup scanner_lookup src_ip OUTPUT scanner_name, approved
```

Then distinguish approved scanners from unknown sources.

---

## 470. What MITRE technique can network discovery map to?

Potentially **T1046 — Network Service Scanning**.

---

# SECTION C — DNS

## 471. Why is DNS valuable to SOC analysts?

DNS can reveal:

```text
Domain lookups
Internal hosts
Malware infrastructure
C2 candidates
DGA behavior
Suspicious newly observed domains
```

---

## 472. Find top DNS queries.

```spl
index=dns
| stats count by query
| sort - count
| head 50
```

---

## 473. Find DNS queries by host.

```spl
index=dns
| stats count by src_ip query
| sort - count
```

---

## 474. What is NXDOMAIN?

**Answer:**

A DNS response indicating that the requested domain does not exist.

---

## 475. Why investigate excessive NXDOMAIN?

It can indicate:

- DGA
    
- Malware
    
- Misconfiguration
    
- Typographical errors
    
- Broken applications
    

---

## 476. Find hosts with high NXDOMAIN counts.

```spl
index=dns response_code=NXDOMAIN
| stats count as nxdomain by src_ip
| sort - nxdomain
```

---

## 477. What is DGA?

**Answer:**

Domain Generation Algorithms can generate large numbers of pseudo-random domains, sometimes used by malware to locate command-and-control infrastructure.

---

## 478. How would you hunt for DGA?

I'd examine:

```text
High query volume
+
Random-looking domains
+
High NXDOMAIN rate
+
Rare domains
+
Host/process correlation
```

---

## 479. Can Splunk detect DGA using only domain length?

**Answer:**

Length alone is weak.

It can be one feature, but I'd combine it with entropy, frequency, NXDOMAIN ratio, reputation and endpoint context.

---

## 480. Scenario: One workstation makes thousands of DNS requests.

**Answer:**

I would determine:

1. Which domains?
    
2. Which process?
    
3. Which user?
    
4. NXDOMAIN percentage?
    
5. Domain age/reputation?
    
6. Is it normal for that host?
    
7. Network connections after resolution?
    

---

# SECTION D — DNS TUNNELING

## 481. What is DNS tunneling?

**Answer:**

Using DNS queries/responses to transport data or maintain communication through DNS infrastructure.

---

## 482. Indicators of DNS tunneling?

Potential indicators:

```text
Long subdomains
High entropy
High query volume
Repeated unusual domain
TXT-heavy behavior
Large/encoded-looking labels
Rare domain
```

---

## 483. Is long DNS traffic automatically tunneling?

**Answer:**

No.

CDNs, security products and legitimate applications can generate unusual DNS patterns.

---

## 484. Find unusually long DNS queries.

Example:

```spl
index=dns
| eval query_length=len(query)
| stats avg(query_length) as avg_length
        max(query_length) as max_length
        count by src_ip
| sort - max_length
```

---

## 485. What would you correlate next?

```text
DNS query
↓
Source host
↓
Process
↓
Destination IP
↓
Outbound connection
↓
Bytes transferred
```

---

## 486. What MITRE technique may apply?

**T1071.004 — Application Layer Protocol: DNS**, depending on the observed behavior.

---

# SECTION E — PROXY / WEB TRAFFIC

## 487. Why are proxy logs useful?

They can show:

- User
    
- URL/domain
    
- HTTP method
    
- Destination
    
- Category
    
- Action
    
- Bytes
    
- User agent
    

---

## 488. Find top accessed domains.

```spl
index=proxy
| stats count by dest_domain
| sort - count
| head 50
```

---

## 489. Find users accessing a suspicious domain.

```spl
index=proxy dest_domain="example.com"
| stats count by user src_ip
```

---

## 490. What should you investigate after identifying a suspicious domain?

```text
Who accessed it?
When?
From which host?
How often?
What URL?
What response?
What process?
Was a file downloaded?
What happened afterward?
```

---

## 491. What is a user-agent?

**Answer:**

A value identifying the client software making an HTTP request.

---

## 492. Why can unusual user-agents be useful?

Attack tools and malware may use unusual or uncommon HTTP clients.

But user-agent strings can also be spoofed.

---

## 493. Detect rare user-agents.

```spl
index=proxy
| stats count by user_agent
| sort count
| head 20
```

---

## 494. Is a rare user-agent malicious?

No.

It is simply a hunting clue.

---

## 495. Find large outbound HTTP transfers.

```spl
index=proxy
| stats sum(bytes_out) as outbound by user src_ip dest_domain
| sort - outbound
| head 50
```

---

# SECTION F — COMMAND AND CONTROL

## 496. What is C2?

**Answer:**

Command and Control is communication between compromised systems and attacker-controlled infrastructure.

---

## 497. What can C2 look like?

Examples:

```text
Periodic beaconing
HTTPS
DNS
TCP
WebSocket
Cloud services
Custom protocols
```

---

## 498. What is beaconing?

**Answer:**

Repeated communications at relatively regular intervals.

Example:

```text
10:00
10:05
10:10
10:15
10:20
```

---

## 499. How would you hunt for beaconing?

Look for:

```text
Repeated destination
+
Regular time intervals
+
Similar packet/byte size
+
Long duration
```

---

## 500. Example SPL concept:

```spl
index=network
| bin _time span=5m
| stats count avg(bytes_out) as avg_out by src_ip dest_ip _time
| sort src_ip dest_ip _time
```

Then investigate repeated patterns.

---

# SECTION G — C2 INVESTIGATION

## 501. Scenario: Endpoint connects to the same external IP every 5 minutes.

What do you do?

**Answer:**

I'd investigate:

```text
Destination reputation
↓
Domain
↓
TLS information
↓
Process owning connection
↓
User
↓
Frequency
↓
Bytes
↓
First-seen date
↓
Other hosts contacting destination
```

---

## 502. Why is regular timing suspicious?

Malware may use scheduled beaconing.

But legitimate applications can also communicate periodically.

---

## 503. What makes beaconing more suspicious?

For example:

```text
Unknown external destination
+
Rare destination
+
Regular interval
+
Unusual process
+
Recently created executable
```

---

## 504. What MITRE technique could apply?

Potentially **T1071 — Application Layer Protocol**, depending on the protocol and behavior.

---

## 505. What if the C2 destination is a legitimate cloud provider?

**Answer:**

That does not automatically make it benign.

Attackers can abuse legitimate infrastructure.

I'd investigate the actual domain, process, account, certificate/context, timing and behavior.

---

# SECTION H — VPN INVESTIGATION

## 506. What VPN logs are important?

Typical fields:

```text
user
src_ip
assigned_ip
country/geolocation
login status
MFA status
device
timestamp
```

---

## 507. Detect VPN failures.

```spl
index=vpn action=failure
| stats count by user src_ip
| sort - count
```

---

## 508. Detect VPN success.

```spl
index=vpn action=success
| stats count by user src_ip
```

---

## 509. Scenario: 30 VPN failures followed by success.

**Answer:**

Potential credential attack.

I would investigate:

```text
Source IP
↓
User
↓
MFA result
↓
Assigned VPN IP
↓
Internal activity
↓
Authentication
↓
Endpoint activity
```

---

## 510. What is impossible travel?

**Answer:**

A detection concept where a user's authentication locations appear physically impossible within the observed time.

---

## 511. Is impossible travel proof of compromise?

**Answer:**

No.

VPNs, proxies, mobile networks, cloud gateways and geolocation errors can produce false positives.

---

## 512. Example hunting query:

```spl
index=vpn action=success
| stats values(src_ip) as source_ips
        values(country) as countries
        earliest(_time) as first_seen
        latest(_time) as last_seen
        by user
```

Then investigate users with unusual geographic/source diversity.

---

# SECTION I — IDS / IPS

## 513. What is IDS?

Intrusion Detection System.

It detects suspicious activity but generally doesn't block it.

---

## 514. What is IPS?

Intrusion Prevention System.

It can detect and actively block traffic.

---

## 515. Should an IDS alert be treated as compromise?

No.

It is an indicator requiring validation.

---

## 516. What would you investigate from an IDS alert?

```text
Signature
Source
Destination
Port
Payload/context
Action
Affected host
Repeated attempts
Related events
```

---

## 517. Scenario: IDS detects exploitation attempt against a server.

What next?

**Answer:**

Check whether the traffic was blocked and whether the target shows evidence of successful exploitation.

---

## 518. Search related traffic.

```spl
index=firewall
src_ip="ATTACKER_IP"
dest_ip="SERVER_IP"
earliest=-30m
latest=+30m
```

Then correlate endpoint telemetry.

---

## 519. Why is endpoint confirmation important?

Because network detection may show an attempt, while endpoint telemetry can establish whether execution or compromise actually occurred.

---

## 520. What if there are no endpoint logs?

**Answer:**

I'd use the available network, authentication, DNS, proxy, firewall and other telemetry while documenting the visibility limitation.

---

# SECTION J — DATA EXFILTRATION

## 521. What is data exfiltration?

**Answer:**

Unauthorized transfer of data outside the organization.

---

## 522. What are potential indicators?

```text
Large outbound transfer
+
Unusual destination
+
Unusual time
+
Sensitive system
+
Unusual process/user
```

---

## 523. Find top outbound data sources.

```spl
index=network
| stats sum(bytes_out) as outbound by src_ip
| sort - outbound
| head 20
```

---

## 524. Is high outbound traffic automatically exfiltration?

No.

Backups, software updates, cloud synchronization and legitimate business applications can generate large transfers.

---

## 525. What is a better approach?

Compare:

```text
Volume
+
Destination
+
User
+
Asset
+
Time
+
Process
+
Baseline
```

---

## 526. Scenario: Finance server sends 50 GB to an unknown external IP at 2 AM.

How do you investigate?

**Answer:**

I'd prioritize it because of asset sensitivity and unusual timing.

Then:

```text
Identify process
↓
Identify account
↓
Identify destination
↓
Check DNS
↓
Check firewall/proxy
↓
Check endpoint
↓
Determine data type
↓
Determine authorization
```

---

## 527. What if the destination is Google Drive?

**Answer:**

Still investigate.

Legitimate cloud services can be abused for data exfiltration.

---

## 528. What is "living off trusted services"?

**Answer:**

Using legitimate services or infrastructure to perform malicious activity, making detection more difficult.

---

## 529. Why is destination reputation alone insufficient?

Because reputation tells you about the infrastructure, not necessarily the intent of this particular connection.

---

## 530. What is the strongest evidence?

There isn't one universal strongest indicator.

A correlated chain of independent evidence is generally much stronger.

---

# SECTION K — FULL NETWORK ATTACK WALKTHROUGH

## 531. Scenario: External scanning → Exploitation → C2

The interviewer says:

> "Walk me through the investigation."

### Your answer:

```text
Internet IP
    ↓
Port scanning
    ↓
Exploit attempt
    ↓
Successful connection
    ↓
Endpoint process
    ↓
Outbound C2
```

---

## 532. First search?

```spl
index=firewall src_ip="ATTACKER_IP"
| stats count by dest_ip dest_port action
| sort - count
```

---

## 533. What next?

Identify the targeted server and investigate IDS/IPS:

```spl
index=ids src_ip="ATTACKER_IP"
dest_ip="SERVER_IP"
```

---

## 534. Then?

Search endpoint activity:

```spl
index=endpoint host="SERVER01"
earliest=-1h
latest=+1h
```

---

## 535. What are you looking for?

```text
New process
↓
Unexpected executable
↓
Shell
↓
PowerShell
↓
Persistence
↓
Network connection
```

---

## 536. Then search outbound connections.

```spl
index=firewall src_ip="SERVER_IP" action=allowed
| stats count sum(bytes_out) as bytes_out by dest_ip dest_port
| sort - bytes_out
```

---

## 537. What if you find regular communication with an external IP?

Investigate it as a potential C2 candidate.

---

## 538. How do you determine scope?

Search the destination across the environment:

```spl
index=firewall dest_ip="SUSPECT_IP"
| stats dc(src_ip) as affected_hosts by dest_ip
```

---

## 539. Why is scope important?

Because one compromised host is very different from:

```text
1 host
vs
10 hosts
vs
100 hosts
```

---

## 540. What would you escalate?

Evidence of:

- Successful exploitation
    
- Malware execution
    
- C2
    
- Credential theft
    
- Lateral movement
    
- Persistence
    
- Data exfiltration
    

---

# SECTION L — ADVANCED NETWORK SCENARIOS

## 541. Scenario: One internal host contacts 1,000 external IPs.

Is it malicious?

**Answer:**

Not automatically.

Investigate whether the host is:

- Proxy
    
- Scanner
    
- CDN infrastructure
    
- Security tool
    
- NAT gateway
    
- Developer system
    
- Compromised endpoint
    

---

## 542. Scenario: One host contacts many destinations on port 443.

What does it mean?

Potentially:

```text
Browser activity
API activity
Software updates
CDN communication
Scanning
Malware
```

Port 443 alone tells us very little.

---

## 543. Scenario: One workstation communicates with an unusual country.

What do you do?

Check:

```text
User
VPN
Process
Domain
Destination reputation
Historical behavior
Other users
Authentication
```

---

## 544. Scenario: Firewall says blocked, IDS says attack.

Is there a contradiction?

Not necessarily.

Different tools observe different points in the traffic path and may record different stages/actions.

---

## 545. Scenario: IDS says exploitation but firewall allowed the traffic.

What next?

Investigate the destination endpoint to determine whether exploitation succeeded.

---

## 546. Scenario: DNS shows malicious domain but proxy shows no connection.

Possible reasons?

```text
DNS resolution only
Cached result
Different network path
Proxy visibility gap
Direct connection
False positive
```

---

## 547. Scenario: Endpoint says process connected to IP but firewall has no record.

What could explain it?

```text
Telemetry gap
Different firewall path
Local traffic
Incorrect fields
Logging delay
Data loss
```

---

## 548. How do you handle conflicting telemetry?

**Answer:**

Don't immediately assume one source is wrong.

I'd compare:

```text
Timestamp
Host
Source/destination
Collection point
Event generation
Ingestion delay
Field normalization
```

Then establish which telemetry provides authoritative evidence for that question.

---

## 549. What makes a strong network investigation?

```text
Network
+
DNS
+
Firewall
+
Proxy
+
Authentication
+
Endpoint
+
Threat intelligence
+
Asset context
```

---

# 550. FINAL NETWORK INTERVIEW CHALLENGE

### Interviewer:

> **"A workstation is communicating with an unknown external IP every five minutes. Explain your complete Splunk investigation."**

### Strong answer:

> "First, I would validate the communication and establish whether the pattern is genuinely periodic. I would identify the source host, user, destination IP, destination port, protocol and time range."

Then:

```text
                  UNKNOWN IP
                      ↓
                Validate traffic
                      ↓
             Identify source host
                      ↓
                  Identify user
                      ↓
              Check destination
             /        |        \
          DNS      Threat Intel  WHOIS/context
            \        |        /
                  ↓
              C2 hypothesis
                  ↓
          Identify owning process
                  ↓
             EDR investigation
                  ↓
          File/hash investigation
                  ↓
        Authentication activity
                  ↓
          Persistence checks
                  ↓
         Lateral movement checks
                  ↓
              Scope analysis
                  ↓
          Malicious / Benign?
             /          \
          Benign       Malicious
             ↓             ↓
          Close        IR Playbook
```

### Your SPL starting point:

```spl
index=network
src_ip="10.10.10.50"
earliest=-24h
latest=now
| stats count
        sum(bytes_out) as bytes_out
        sum(bytes_in) as bytes_in
        values(dest_port) as ports
        by dest_ip
| sort - count
```

Then:

```spl
index=dns
src_ip="10.10.10.50"
earliest=-24h
latest=now
| stats count by query
| sort - count
```

Then:

```spl
index=endpoint
host="WORKSTATION01"
earliest=-24h
latest=now
| table _time user process_name parent_process_name command_line dest_ip dest_port
| sort 0 _time
```

### Final interview statement:

> **"I wouldn't label the traffic C2 merely because it occurs every five minutes. I'd correlate periodicity with destination reputation, DNS, owning process, user, endpoint behavior, authentication, persistence and whether other hosts show the same pattern. If multiple independent indicators support compromise, I'd escalate and follow the incident-response playbook."**

---

# 🔥 The Network SOC Mental Model

Memorize this:

```text
             NETWORK ALERT
                   ↓
              WHO?
                   ↓
             SOURCE HOST
                   ↓
              DESTINATION
                   ↓
               WHEN?
                   ↓
              WHAT PORT?
                   ↓
             WHAT PROTOCOL?
                   ↓
             ALLOWED/BLOCKED
                   ↓
                 DNS
                   ↓
               PROCESS
                   ↓
                USER
                   ↓
            WHAT HAPPENED NEXT?
                   ↓
              ATTACK CHAIN
                   ↓
                SCOPE
                   ↓
                IMPACT
                   ↓
          RESPONSE / ESCALATION
```

That framework will work for **firewall, IDS, DNS, proxy, VPN and C2 interviews**.

---

# Splunk SOC Interview — Part 6

## Q551–650 — Splunk Enterprise Security, Correlation Searches, Risk-Based Alerting, Threat Intelligence & MITRE ATT&CK

This is the **L2 / experienced-SOC section**. The interviewer is now testing whether you understand how Splunk is used as an actual **SIEM and detection platform**, not just as a search tool.

---

# SECTION A — SPLUNK ENTERPRISE SECURITY

## 551. What is Splunk Enterprise Security?

**Answer:**

Splunk Enterprise Security (ES) is a security-focused solution built on Splunk that provides capabilities such as:

- Security monitoring
    
- Correlation searches
    
- Risk analysis
    
- Notable events
    
- Investigation
    
- Threat intelligence
    
- Security dashboards
    
- Incident management workflows
    

---

## 552. What is the difference between Splunk and Splunk ES?

**Answer:**

Think:

```text
Splunk
   ↓
General data platform
   ↓
Search / analytics / dashboards

Splunk ES
   ↓
Security-focused capabilities
   ↓
Detection / correlation / risk / investigation
```

---

## 553. What is a notable event?

**Answer:**

A notable event is a security alert generated by a correlation search or other detection mechanism in Splunk ES.

It represents something that requires analyst attention.

---

## 554. Is a notable event the same as an incident?

**Answer:**

Not necessarily.

A notable is an alert.

Multiple related alerts may ultimately represent one security incident.

```text
Alert 1
Alert 2
Alert 3
   ↓
Potential Incident
```

---

## 555. What is a correlation search?

**Answer:**

A scheduled or triggered search designed to identify suspicious behavior by correlating security telemetry.

Example:

```spl
index=windows EventCode=4625
| stats count by src_ip,user
| where count > 50
```

---

## 556. Why use correlation searches?

Because individual events often don't provide enough context.

Correlation allows:

```text
Authentication
+
Endpoint
+
Network
+
DNS
=
Higher-confidence detection
```

---

## 557. What makes a good correlation search?

It should have:

- Clear security objective
    
- Relevant data
    
- Reasonable threshold
    
- Low unnecessary noise
    
- Useful context
    
- Appropriate severity
    
- MITRE mapping where applicable
    
- Documented response process
    

---

## 558. What is a false positive?

An alert that appears suspicious but represents legitimate activity.

---

## 559. What is a false negative?

Malicious activity that the detection fails to identify.

---

## 560. Which is worse?

**Answer:**

Both matter.

In security:

```text
False positive
→ Analyst fatigue

False negative
→ Missed attack
```

Detection engineering tries to balance both.

---

# SECTION B — CORRELATION SEARCH SCENARIOS

## 561. Build a brute-force correlation search.

```spl
index=windows EventCode=4625
| stats count as failures by src_ip user
| where failures > 50
```

Then enrich with asset or threat intelligence context.

---

## 562. Why is this detection incomplete?

Because the threshold alone doesn't account for:

- Approved scanners
    
- Service accounts
    
- Application failures
    
- Internal tools
    
- Distributed attacks
    

---

## 563. Improve the brute-force detection.

```spl
index=windows EventCode=4625
| stats count as failures
        dc(user) as unique_users
        values(user) as users
        by src_ip
| where failures > 50
```

Now you have more context.

---

## 564. How would you detect password spraying?

```spl
index=windows EventCode=4625
| stats dc(user) as targeted_users
        count as failures
        values(user) as users
        by src_ip
| where targeted_users >= 10
```

---

## 565. How would you increase confidence?

Correlate with:

```text
Failed authentication
+
Successful authentication
+
Unusual source
+
Privileged target
```

---

## 566. Detect failed followed by successful authentication.

```spl
index=windows (EventCode=4625 OR EventCode=4624)
| stats
    count(eval(EventCode=4625)) as failures
    count(eval(EventCode=4624)) as successes
    by user src_ip
| where failures > 10 AND successes > 0
```

---

## 567. Why is correlation better than a single failed login?

Because a single failed login is extremely common.

A sequence such as:

```text
50 failures
↓
success
↓
privileged activity
↓
PowerShell
```

is considerably more interesting.

---

## 568. What is detection fidelity?

**Answer:**

How accurately a detection identifies genuinely relevant malicious activity while minimizing unnecessary alerts.

---

## 569. How do you improve detection fidelity?

Use:

```text
Better telemetry
+
Context
+
Enrichment
+
Baselines
+
Correlation
+
Threshold tuning
```

---

## 570. What is detection tuning?

**Answer:**

Adjusting detection logic based on real-world results to reduce noise and improve useful detection.

---

# SECTION C — NOTABLE EVENTS

## 571. What information should a notable contain?

Ideally:

```text
Alert name
Severity
Time
User
Host
Source IP
Destination
Detection reason
MITRE technique
Risk
Relevant fields
Investigation link
```

---

## 572. Why is context important in an alert?

Because an analyst shouldn't have to reconstruct everything from scratch before understanding why the alert fired.

---

## 573. What is alert fatigue?

**Answer:**

When analysts receive excessive low-value alerts and become overwhelmed.

---

## 574. Why is alert fatigue dangerous?

Analysts may:

- Miss important alerts
    
- Close alerts too quickly
    
- Become less attentive
    
- Spend time on low-value events
    

---

## 575. Scenario: 1,000 alerts/day and 90% are benign.

What would you do?

**Answer:**

I'd analyze:

```text
Top alert sources
↓
False-positive reasons
↓
Common users/hosts
↓
Repeated patterns
↓
Thresholds
↓
Missing enrichment
```

Then tune detections without weakening meaningful coverage.

---

## 576. Should you simply increase every threshold?

No.

That can reduce visibility and create false negatives.

---

## 577. What is suppression?

Reducing or suppressing repeated known alert conditions under controlled circumstances.

---

## 578. Why is suppression risky?

Attackers may abuse exceptions.

Suppression should have:

- Owner
    
- Reason
    
- Scope
    
- Expiration/review
    
- Approval
    

---

## 579. What is a notable event lifecycle?

Example:

```text
Generated
   ↓
Assigned
   ↓
Investigating
   ↓
Confirmed / Benign
   ↓
Contained / Escalated
   ↓
Closed
```

---

## 580. What should be included when closing an alert?

A concise evidence-based conclusion.

Example:

```text
Detection triggered due to 60 failed logins.
Source was an approved vulnerability scanner.
No successful authentication observed.
No endpoint compromise identified.
Closed as benign/authorized activity.
```

---

# SECTION D — RISK-BASED ALERTING

## 581. What is Risk-Based Alerting?

**Answer:**

A detection strategy where suspicious behaviors contribute risk rather than every individual behavior necessarily creating a separate high-priority alert.

---

## 582. Why is risk-based alerting useful?

Instead of:

```text
Alert
Alert
Alert
Alert
Alert
```

you can reason:

```text
Low-risk behavior
      +
Suspicious authentication
      +
Endpoint execution
      +
C2
      ↓
Higher overall risk
```

---

## 583. What is a risk score?

A numerical representation of risk associated with an entity or activity.

---

## 584. What is a risk object?

The entity to which risk is associated.

Examples:

```text
User
Host
IP
```

---

## 585. Example:

```text
User = alice
Risk +10 → unusual login
Risk +20 → suspicious PowerShell
Risk +40 → C2
```

Total:

```text
70
```

This may warrant investigation.

---

## 586. Why is entity-based risk useful?

Because multiple weak indicators can become meaningful when associated with the same entity.

---

## 587. Scenario: Three alerts all involve the same workstation.

What do you do?

**Answer:**

I'd correlate them by host and timeline rather than treating them as unrelated alerts.

---

## 588. What entities are commonly correlated?

```text
User
Host
IP
Asset
Account
Domain
```

---

## 589. What is risk aggregation?

Combining multiple risk contributions associated with an entity.

---

## 590. What is the danger of risk scoring?

Bad detections can create inflated or misleading risk scores.

---

# SECTION E — THREAT INTELLIGENCE

## 591. What is threat intelligence?

**Answer:**

Information about threats, indicators, adversaries, infrastructure, tactics and techniques used to support security decisions.

---

## 592. What is an IOC?

Indicator of Compromise.

Examples:

```text
IP
Domain
URL
Hash
Email address
```

---

## 593. Is an IOC proof of compromise?

No.

An IOC is evidence/clue requiring validation.

---

## 594. What is IOC enrichment?

Adding intelligence context to an event.

Example:

```text
src_ip
↓
Threat intelligence
↓
Malicious reputation?
↓
Threat actor/context?
```

---

## 595. How would you investigate a malicious IP alert?

```text
IP
↓
Who contacted it?
↓
When?
↓
How often?
↓
Which process?
↓
Which user?
↓
DNS/domain?
↓
Data transfer?
↓
Other affected hosts?
```

---

## 596. Find hosts communicating with a suspicious IP.

```spl
index=firewall dest_ip="SUSPICIOUS_IP"
| stats count by src_ip
| sort - count
```

---

## 597. What if the IP is shared hosting/CDN infrastructure?

**Answer:**

Reputation alone becomes less reliable.

I'd investigate the actual domain, URL, process, TLS context and behavioral evidence.

---

## 598. What is an IOC lifecycle?

```text
Identified
↓
Validated
↓
Enriched
↓
Distributed
↓
Detected
↓
Reviewed
↓
Expired/Retired
```

---

## 599. Why should threat intelligence have expiration?

Indicators can become stale.

An IP that was malicious six months ago may no longer represent the same infrastructure.

---

## 600. What is the difference between IOC and TTP?

```text
IOC
→ Specific artifact

TTP
→ Attacker behavior
```

Example:

```text
Malicious IP = IOC

PowerShell execution
= Behavior/TTP
```

---

# SECTION F — MITRE ATT&CK

## 601. What is MITRE ATT&CK?

**Answer:**

A knowledge base describing adversary tactics and techniques based on observed real-world behavior.

---

## 602. Why do SOC analysts use ATT&CK?

For:

- Detection mapping
    
- Investigation
    
- Threat hunting
    
- Reporting
    
- Coverage analysis
    
- Adversary behavior understanding
    

---

## 603. What is a tactic?

The adversary's goal.

Examples:

```text
Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Command and Control
Exfiltration
```

---

## 604. What is a technique?

A method used to accomplish a tactic.

Example:

```text
Execution
   ↓
PowerShell
```

---

## 605. What is a sub-technique?

A more specific technique classification.

---

## 606. PowerShell ATT&CK mapping?

**T1059.001 — PowerShell**

---

## 607. Network Service Scanning?

**T1046**

---

## 608. RDP lateral movement?

Potentially **T1021.001 — Remote Services: RDP**

---

## 609. SMB/Windows Admin Shares?

Potentially **T1021.002**

---

## 610. DNS C2?

Potentially **T1071.004**

---

# SECTION G — DETECTION ENGINEERING

## 611. What is detection engineering?

**Answer:**

The process of designing, implementing, testing, tuning and maintaining detections for malicious behavior.

---

## 612. What should you define before writing a detection?

Ask:

```text
What behavior?
Why malicious?
What telemetry?
What fields?
What threshold?
Expected false positives?
Response?
MITRE mapping?
```

---

## 613. Example detection requirement:

> Detect suspicious PowerShell from Microsoft Office.

Start with:

```text
Telemetry:
Endpoint process data

Behavior:
Office → PowerShell

Risk:
Potential malicious execution
```

---

## 614. Example SPL:

```spl
index=endpoint
parent_process_name IN ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE")
process_name="powershell.exe"
| table _time host user parent_process_name process_name command_line
```

---

## 615. How would you test this detection?

Create/test representative:

```text
Benign Office → PowerShell
Suspicious Office → PowerShell
Different user
Different host
Different command
```

Then measure:

```text
True positives
False positives
Missed cases
```

---

## 616. What is detection coverage?

**Answer:**

The range of relevant malicious behaviors your detections can identify.

---

## 617. What is a detection gap?

A relevant malicious behavior for which you lack sufficient telemetry or detection logic.

---

## 618. Example:

```text
MITRE technique
      ↓
Required telemetry
      ↓
Telemetry missing
      ↓
Detection impossible
```

That's a **visibility gap**, not necessarily a query problem.

---

## 619. What is a detection dependency?

Something required for a detection to function.

Example:

```text
PowerShell detection
↓
Requires PowerShell telemetry
```

---

## 620. Why document detection dependencies?

Because when telemetry breaks, analysts need to understand which detections are affected.

---

# SECTION H — DETECTION TESTING

## 621. What is a detection test?

A controlled test used to determine whether a detection triggers as expected.

---

## 622. What should you test?

```text
Expected malicious behavior
Expected benign behavior
Edge cases
Missing fields
Different users
Different hosts
```

---

## 623. What is a regression test?

A test ensuring that a previously working detection still works after changes.

---

## 624. Why is regression testing important?

Because detection tuning can accidentally break coverage.

---

## 625. Scenario: You tuned a detection and alerts dropped 90%.

Is that automatically good?

**Answer:**

No.

You need to determine whether:

```text
False positives decreased
```

or:

```text
Real detections were suppressed
```

---

## 626. What metrics would you monitor?

Potentially:

- Alert volume
    
- True-positive rate
    
- False-positive rate
    
- Mean time to acknowledge
    
- Mean time to respond
    
- Detection coverage
    
- Suppression rate
    

---

## 627. What is MTTD?

Mean Time To Detect.

---

## 628. What is MTTR?

Mean Time To Respond/Recover, depending on organizational definition.

Always clarify the organization's metric definition.

---

## 629. Why are SOC metrics important?

They help measure operational performance and identify weaknesses.

---

## 630. What is a good SOC metric?

One that supports a meaningful operational decision.

---

# SECTION I — PLAYBOOKS

## 631. What is a SOC playbook?

**Answer:**

A documented procedure for responding to a specific alert or incident type.

---

## 632. Example: Brute-force playbook.

```text
Alert
 ↓
Validate
 ↓
Identify source
 ↓
Identify targeted accounts
 ↓
Check successful authentication
 ↓
Check source reputation
 ↓
Check endpoint activity
 ↓
Determine scope
 ↓
Contain/escalate according to policy
 ↓
Document
```

---

## 633. What should a playbook contain?

At minimum:

```text
Trigger
Objective
Required data
Investigation steps
Decision points
Containment options
Escalation criteria
Evidence requirements
Closure criteria
```

---

## 634. Why are decision points important?

Example:

```text
Successful authentication?
       /       \
     NO         YES
     ↓           ↓
Continue      Investigate
              compromise
```

---

## 635. Should every analyst have permission to isolate hosts?

**Answer:**

No.

Actions must follow organizational authorization and response procedures.

---

# SECTION J — ATTACK PLAYBOOK

## 636. Suspicious PowerShell Playbook

```text
ALERT
 ↓
Validate PowerShell event
 ↓
Identify user/host
 ↓
Analyze command line
 ↓
Check parent process
 ↓
Check child processes
 ↓
Check network connections
 ↓
Check downloaded files
 ↓
Check persistence
 ↓
Check lateral movement
 ↓
Determine malicious/benign
 ↓
Escalate/contain if authorized
```

---

## 637. What if PowerShell was launched by Word?

Increase investigation priority.

Then inspect:

```text
Document
User
Parent process
Command
Network
File creation
EDR
```

---

## 638. What if PowerShell was launched by SCCM?

Could be legitimate enterprise automation.

Validate:

```text
Host
Account
Script
Change ticket
Timing
Expected deployment
```

---

## 639. Why is context so important?

Because:

```text
PowerShell
```

is a tool.

It isn't inherently malicious.

---

## 640. Why is process ancestry valuable?

Because it provides behavioral context.

Example:

```text
services.exe
 ↓
svchost.exe
```

can be normal.

Whereas:

```text
WINWORD.EXE
 ↓
powershell.exe
 ↓
rundll32.exe
```

may warrant investigation.

---

# SECTION K — L2 INVESTIGATION

## 641. What makes an L2 analyst different from L1?

**Answer:**

An L2 analyst generally handles more complex investigations, deeper correlation, threat hunting, detection tuning and escalation.

---

## 642. L1 sees:

```text
Suspicious IP
```

What does L2 ask?

```text
Why?
Who?
What host?
What process?
What communication?
What happened before?
What happened after?
What else is affected?
```

---

## 643. What is hypothesis-driven investigation?

Start with a hypothesis and test it using evidence.

Example:

> "This may be password spraying."

Then search for:

```text
Many users
+
Same source
+
Failed authentication
+
Potential success
```

---

## 644. Why is hypothesis-driven hunting useful?

It prevents random searching and gives the investigation a clear objective.

---

## 645. What is pivoting?

Moving from one investigative entity to another.

Example:

```text
IP
 ↓
User
 ↓
Host
 ↓
Process
 ↓
Domain
 ↓
File
```

---

## 646. What is timeline analysis?

Putting related events into chronological order.

Example:

```text
09:01 Failed login
09:03 Failed login
09:05 Successful login
09:06 PowerShell
09:07 DNS request
09:08 External connection
09:12 Account change
```

This can reveal the attack chain.

---

## 647. Why is timeline analysis powerful?

Because isolated events may look harmless while their sequence reveals malicious behavior.

---

## 648. Scenario: You have five suspicious alerts.

What do you do?

Don't investigate them independently immediately.

First ask:

> **"Could these alerts belong to the same entity, source, host, user or attack timeline?"**

---

## 649. How do you determine incident scope?

Search across:

```text
User
Host
Source IP
Destination IP
Domain
Hash
Process
Account
```

Then determine how many systems/accounts are involved.

---

# 650. FINAL L2 INTERVIEW CHALLENGE

### Interviewer:

> **"Your Splunk ES environment generated three alerts: password spraying, suspicious PowerShell and outbound communication with a threat-intelligence hit. Walk me through your response."**

### Excellent answer:

> "I would first determine whether the three alerts are related. I'd correlate their timestamps, users, hosts, source IPs and destination infrastructure. If they involve the same user or endpoint, I'd build a timeline."

Then:

```text
PASSWORD SPRAY
      ↓
Successful authentication?
      ↓
Affected account
      ↓
Affected host
      ↓
PowerShell execution
      ↓
Process ancestry
      ↓
Command line
      ↓
DNS
      ↓
Outbound connection
      ↓
Threat-intelligence enrichment
      ↓
Persistence
      ↓
Lateral movement
      ↓
Scope
      ↓
Impact
      ↓
Incident?
```

### Example searches:

**Authentication:**

```spl
index=windows
(EventCode=4624 OR EventCode=4625)
user="TARGET_USER"
earliest=-4h
latest=now
| sort 0 _time
```

**PowerShell:**

```spl
index=endpoint
user="TARGET_USER"
process_name="powershell.exe"
earliest=-4h
latest=now
| table _time host user parent_process_name process_name command_line
| sort 0 _time
```

**Network:**

```spl
index=firewall
src_ip="HOST_IP"
earliest=-4h
latest=now
| stats count sum(bytes_out) as bytes_out
        by dest_ip dest_port action
| sort - count
```

**Scope:**

```spl
index=firewall dest_ip="THREAT_IP"
earliest=-24h
latest=now
| stats dc(src_ip) as affected_hosts
        values(src_ip) as hosts
        by dest_ip
```

### Final answer:

> **"I would not treat the three alerts as independent. The combination of credential attack, successful authentication, PowerShell execution and suspicious outbound communication could represent a complete compromise chain. I'd validate each stage, establish scope and impact, preserve the evidence, and follow the organization's incident-response playbook for containment and escalation."**

---

# 🔥 The L2 Formula

For your interview, remember this:

```text
                 ALERT
                   ↓
                VALIDATE
                   ↓
                CORRELATE
                   ↓
                 PIVOT
                   ↓
                TIMELINE
                   ↓
                 SCOPE
                   ↓
                IMPACT
                   ↓
          MITRE ATT&CK MAPPING
                   ↓
            PLAYBOOK DECISION
                   ↓
         CONTAIN / ESCALATE
                   ↓
              DOCUMENT
```

And the **most important L2 sentence**:

> **"I wouldn't make a conclusion from one indicator; I would correlate independent telemetry to establish intent, execution, scope and impact."**

---

## Progress

|Part|Coverage|Questions|
|---|---|--:|
|Part 1|Splunk fundamentals|1–50|
|Part 2|Architecture, ingestion, CIM|51–150|
|Part 3|SPL|151–350|
|Part 4|Windows + AD|351–450|
|Part 5|Network + DNS + VPN + IDS/IPS|451–550|
|**Part 6**|**Splunk ES + RBA + TI + MITRE + Detection**|**551–650**|

---
# Splunk SOC Interview — Part 7

## Q651–750 — EDR, Malware, PowerShell, Persistence, Credential Access, Lateral Movement & Ransomware

This section is designed for **L1/L2 interviews where the interviewer gives you an endpoint alert and expects you to investigate it in Splunk**.

The key mindset:

> **Don't investigate the alert in isolation. Reconstruct what happened before, during, and after the alert.**

---

# SECTION A — EDR + SPLUNK

## 651. What is EDR?

**Answer:**

Endpoint Detection and Response provides endpoint visibility and detection capabilities around things such as:

- Processes
    
- Command lines
    
- Network connections
    
- Files
    
- Registry
    
- User activity
    
- Persistence
    
- Security detections
    

---

## 652. Difference between EDR and SIEM?

|EDR|SIEM|
|---|---|
|Endpoint-focused|Broad security visibility|
|Process telemetry|Logs from many sources|
|Endpoint response|Correlation/investigation|
|Host-centric|Enterprise-wide|

A SIEM can ingest EDR telemetry.

---

## 653. Why integrate EDR with Splunk?

**Answer:**

To correlate endpoint behavior with:

```text
Authentication
+
Firewall
+
DNS
+
Proxy
+
VPN
+
Threat intelligence
```

---

## 654. What endpoint fields are valuable?

Common examples:

```text
host
user
process_name
parent_process_name
command_line
hash
dest_ip
dest_port
file_path
signature
action
```

Exact names depend on the EDR integration.

---

## 655. What is process ancestry?

The parent-child relationship between processes.

Example:

```text
explorer.exe
     ↓
WINWORD.EXE
     ↓
powershell.exe
     ↓
rundll32.exe
```

---

## 656. Why is process ancestry important?

It helps identify unusual execution chains.

---

## 657. Is a suspicious process name enough?

No.

Attackers can:

- Rename malware
    
- Masquerade as legitimate programs
    
- Execute through legitimate tools
    

Behavior and context matter.

---

## 658. What is process masquerading?

**Answer:**

Making a malicious process appear to be a legitimate process.

Example concept:

```text
Legitimate:
C:\Windows\System32\svchost.exe

Suspicious:
C:\Users\Public\svchost.exe
```

The name alone is not enough; path and behavior matter.

---

## 659. What would you check?

```text
Process name
Path
Hash
Signature
Parent
Child processes
User
Network connections
Creation time
```

---

## 660. Scenario: `powershell.exe` runs from an unusual directory.

What do you do?

Investigate:

```text
Path
Parent process
Command line
User
Hash/signature
Network activity
Child processes
File creation
```

---

# SECTION B — MALWARE INVESTIGATION

## 661. What is malware?

**Answer:**

Malicious software designed to perform unauthorized or harmful actions.

---

## 662. Common malware categories?

Examples:

- Trojan
    
- Ransomware
    
- Infostealer
    
- RAT
    
- Worm
    
- Downloader
    
- Backdoor
    
- Rootkit
    

---

## 663. What is a malware hash?

A cryptographic identifier calculated from a file.

---

## 664. Why are hashes useful?

They can help correlate the same file across endpoints and intelligence sources.

---

## 665. Is a hash alone enough to determine maliciousness?

No.

A hash may be:

- Unknown
    
- Changed
    
- Repacked
    
- New
    
- Legitimate
    

Use multiple evidence sources.

---

## 666. Search for a suspicious hash.

```spl
index=endpoint hash="SUSPICIOUS_HASH"
| stats count by host user process_name file_path
```

---

## 667. How do you determine malware scope?

Search the hash across all endpoints.

```spl
index=endpoint hash="SUSPICIOUS_HASH"
| stats dc(host) as affected_hosts
        values(host) as hosts
```

---

## 668. Why is scope important?

Because:

```text
1 endpoint
```

and:

```text
50 endpoints
```

represent very different incidents.

---

## 669. What if the hash appears on multiple systems?

Determine:

```text
Same timestamp?
Same user?
Same file path?
Same parent process?
Same network activity?
```

This can reveal propagation.

---

## 670. What is malware execution evidence?

Examples:

```text
Process creation
File execution
EDR detection
Network communication
Persistence
Child processes
```

---

# SECTION C — DOWNLOAD → EXECUTION

## 671. Scenario: User downloads an executable.

Is that malicious?

No.

---

## 672. What makes it suspicious?

For example:

```text
Unknown domain
+
Executable
+
Unusual user
+
Immediate execution
+
PowerShell
+
Outbound C2
```

---

## 673. What is the attack chain?

```text
Browser
 ↓
Malicious domain
 ↓
Download
 ↓
Executable
 ↓
Execution
 ↓
Persistence
 ↓
C2
```

---

## 674. How would you investigate the download?

Search:

```text
Proxy
DNS
EDR
Firewall
File telemetry
```

---

## 675. What should you document?

```text
URL/domain
Timestamp
User
Host
Filename
Hash
Process
Destination IP
```

---

# SECTION D — POWERSHELL DEEP DIVE

## 676. Why do attackers use PowerShell?

Because it is:

- Built into Windows
    
- Powerful
    
- Scriptable
    
- Widely trusted
    
- Useful for administration
    

---

## 677. What is PowerShell execution policy?

**Answer:**

A Windows PowerShell mechanism intended to control script execution behavior.

It should not be treated as a complete security boundary.

---

## 678. What is encoded PowerShell?

Commands can be passed in encoded form.

Common indicator:

```text
-EncodedCommand
```

---

## 679. What should you do with encoded commands?

Decode the command **in an authorized investigation environment** and analyze its behavior.

---

## 680. What would make encoded PowerShell highly suspicious?

```text
EncodedCommand
+
Internet connection
+
Office parent
+
Downloaded payload
+
Obfuscated strings
```

---

## 681. What is PowerShell obfuscation?

**Answer:**

Techniques used to make PowerShell code harder to understand or detect.

---

## 682. What should detection focus on?

Don't rely only on keywords.

Look for combinations such as:

```text
Parent process
Command behavior
Network activity
Script characteristics
User
Host
File activity
```

---

## 683. Example SPL:

```spl
index=endpoint
process_name="powershell.exe"
| search command_line="*-EncodedCommand*"
| table _time host user parent_process_name command_line
```

---

## 684. Scenario: PowerShell is launched by `WINWORD.EXE`.

What ATT&CK technique?

Potentially:

**T1059.001 — PowerShell**

Combined with malicious document behavior depending on the evidence.

---

## 685. What do you investigate next?

```text
Word document
↓
User
↓
PowerShell command
↓
Network
↓
Downloaded files
↓
Child process
↓
Persistence
```

---

# SECTION E — CREDENTIAL ACCESS

## 686. What is credential access?

**Answer:**

Techniques used to obtain credentials, password material, authentication tokens or other secrets.

---

## 687. Common credential-access techniques?

Examples:

- Credential dumping
    
- Keylogging
    
- Browser credential theft
    
- LSASS targeting
    
- Kerberoasting
    
- Password spraying
    
- Token theft
    

---

## 688. What is LSASS?

Local Security Authority Subsystem Service.

It handles important Windows security/authentication functions.

---

## 689. Why is LSASS important?

Attackers may attempt to access its memory to obtain credential material.

---

## 690. What would suspicious LSASS access look like?

Look for:

```text
Unusual process
↓
Access to LSASS
↓
Suspicious privileges
↓
Dump/file creation
↓
Credential use afterward
```

---

# SECTION F — CREDENTIAL DUMPING

## 691. What is credential dumping?

Attempting to extract credentials or credential material from a system.

---

## 692. Why is credential dumping dangerous?

Credentials can enable:

```text
Privilege escalation
Lateral movement
Persistence
Domain compromise
```

---

## 693. What telemetry helps?

Potentially:

- EDR process telemetry
    
- Sysmon
    
- Windows Security
    
- Process access events
    
- File creation
    
- Authentication logs
    

---

## 694. What would you do after detecting credential dumping?

**Answer:**

I would immediately investigate:

```text
Which account?
Which host?
What process?
What privileges?
What credential source?
What credentials may be exposed?
Did the attacker use them elsewhere?
```

---

## 695. What is the important pivot?

From:

```text
Compromised host
```

to:

```text
Accounts used by that host
```

Then search those accounts across the environment.

---

## 696. Scenario: Credential dumping on workstation.

What next?

```text
Credential access
↓
Identify exposed accounts
↓
Search authentication
↓
Find other hosts
↓
Identify lateral movement
↓
Check privileged accounts
```

---

## 697. Why investigate authentication after credential theft?

Because stolen credentials may be immediately used for lateral movement.

---

## 698. Example:

```spl
index=windows EventCode=4624
user="COMPROMISED_USER"
| stats values(host) as hosts
        values(src_ip) as sources
        by user
```

---

## 699. What is credential exposure scope?

The number and privilege level of accounts potentially exposed.

---

## 700. Which is more serious?

```text
Normal user credential
```

versus:

```text
Domain Admin credential
```

The privileged credential exposure generally represents significantly greater potential impact.

---

# SECTION G — LATERAL MOVEMENT

## 701. What is lateral movement?

Moving from one system to another after gaining access.

---

## 702. Common Windows lateral movement protocols?

```text
RDP
SMB
WinRM
WMI
Remote services
```

---

## 703. How can valid accounts facilitate lateral movement?

An attacker can use stolen legitimate credentials to access additional systems.

---

## 704. Why is valid-account activity difficult to detect?

Because the authentication itself may look legitimate.

---

## 705. What context helps?

```text
Source host
Destination host
User
Time
Normal behavior
Privilege
Protocol
Process
```

---

## 706. Scenario: User authenticates to 15 servers in 10 minutes.

Is that malicious?

Not automatically.

It could be:

- Administrator
    
- Deployment system
    
- Backup system
    
- Automation
    
- Attacker
    

---

## 707. How do you investigate it?

```spl
index=windows EventCode=4624
user="USER"
| stats dc(host) as destination_hosts
        values(host) as hosts
        values(src_ip) as sources
        by user
```

---

## 708. What makes it more suspicious?

```text
Rare source workstation
+
Privileged account
+
Unusual time
+
Many destinations
+
PowerShell/WMI
```

---

## 709. What is RDP lateral movement?

Using Remote Desktop Protocol to move between systems.

---

## 710. What is SMB lateral movement?

Using SMB/Windows administrative shares or related mechanisms for remote operations.

---

# SECTION H — PERSISTENCE

## 711. Why do attackers establish persistence?

To maintain access after:

- Reboot
    
- Logout
    
- Credential changes
    
- Initial access removal
    

---

## 712. What are common persistence mechanisms?

```text
Scheduled Tasks
Services
Registry Run Keys
Startup folders
Accounts
WMI
```

---

## 713. Detect scheduled task creation.

```spl
index=windows EventCode=4698
| table _time host SubjectUserName TaskName
```

---

## 714. What makes a scheduled task suspicious?

Consider:

```text
Task name
Author
Binary path
User
Trigger
Creation time
Parent process
Network behavior
```

---

## 715. What is service persistence?

Creating/modifying a service to execute code.

---

## 716. What is Registry Run persistence?

Configuring a program to execute when a user logs in.

---

## 717. Scenario: New service appears immediately after malware execution.

How do you investigate?

```text
Malware execution
↓
Service creation
↓
Binary path
↓
Account
↓
Startup behavior
↓
Network communication
```

---

## 718. Why is timing important?

If:

```text
10:01 malware executes
10:02 service created
10:03 C2 begins
```

the relationship becomes significant.

---

## 719. What is persistence hunting?

Searching for mechanisms that allow attackers to maintain access.

---

## 720. Why should persistence be checked even after malware is removed?

Because another persistence mechanism may remain.

---

# SECTION I — RANSOMWARE

## 721. What is ransomware?

Malware that typically encrypts or otherwise disrupts data/systems and demands payment.

---

## 722. What are common ransomware indicators?

Potentially:

```text
Mass file modifications
High file-write activity
Shadow-copy deletion
Security-tool tampering
Credential theft
Lateral movement
Encryption behavior
Ransom note creation
```

---

## 723. What should be investigated first?

Determine whether encryption is actively occurring and establish scope.

---

## 724. What is the attack chain?

A common pattern:

```text
Initial Access
      ↓
Credential Access
      ↓
Lateral Movement
      ↓
Privilege Escalation
      ↓
Defense Evasion
      ↓
Data Collection
      ↓
Encryption
      ↓
Extortion
```

---

## 725. Why is ransomware a high-priority incident?

Because it can rapidly impact availability and potentially cause large-scale operational disruption.

---

## 726. What should an L1 analyst do?

Follow the organization's ransomware playbook and immediately escalate according to severity and authorization.

---

## 727. What should you search for in Splunk?

```spl
index=endpoint
| search process_name IN ("powershell.exe","cmd.exe")
| table _time host user process_name parent_process_name command_line
```

Then investigate file activity and EDR detections.

---

## 728. What other telemetry is important?

```text
Authentication
EDR
Windows
Firewall
SMB
DNS
VPN
Backup systems
```

---

## 729. Why investigate backups?

Attackers may target backup infrastructure to make recovery more difficult.

---

## 730. Why investigate Domain Controllers?

Because attackers may target identity infrastructure to expand control over the environment.

---

# SECTION J — RANSOMWARE ATTACK WALKTHROUGH

## 731. Scenario:

> "EDR reports suspicious PowerShell. Five minutes later, hundreds of files are modified."

What do you think?

Potential ransomware or another destructive activity is possible.

---

## 732. First step?

Validate the EDR alert.

---

## 733. Second step?

Build a timeline:

```text
PowerShell
↓
Child process
↓
File activity
↓
Network
↓
Authentication
↓
Lateral movement
```

---

## 734. Search PowerShell:

```spl
index=endpoint
process_name="powershell.exe"
host="HOST01"
earliest=-30m
latest=now
| table _time user process_name parent_process_name command_line
| sort 0 _time
```

---

## 735. Search network activity:

```spl
index=firewall
src_ip="HOST_IP"
earliest=-30m
latest=now
| stats count by dest_ip dest_port action
| sort - count
```

---

## 736. Search authentication:

```spl
index=windows
(EventCode=4624 OR EventCode=4625)
src_ip="HOST_IP"
earliest=-1h
latest=now
| stats count by EventCode user host
```

---

## 737. Search affected systems.

Look for other hosts showing:

```text
Same process
Same hash
Same user
Same command
Same network destination
Same file behavior
```

---

## 738. What is the key question?

> **"Is this one infected endpoint, or the beginning of an enterprise-wide attack?"**

---

## 739. How do you determine scope?

Search across:

```text
Hash
Host
User
Source IP
Process
Command line
Destination IP
```

---

## 740. What should you avoid?

Do not make unauthorized destructive changes or isolate systems outside your response permissions.

Follow the organization's incident-response procedures.

---

# SECTION K — ATTACK CHAIN CORRELATION

## 741. Scenario:

```text
Phishing
 ↓
PowerShell
 ↓
Credential Dumping
 ↓
RDP
 ↓
C2
 ↓
Ransomware
```

What should the analyst do?

Treat it as a potential multi-stage incident rather than six unrelated alerts.

---

## 742. How do you correlate the chain?

Use:

```text
User
Host
Source IP
Destination IP
Process
Hash
Domain
Timestamp
```

---

## 743. Why is timestamp correlation important?

Because attack stages often occur in sequence.

---

## 744. Example:

```text
08:01 Phishing click
08:03 PowerShell
08:05 Credential access
08:08 RDP
08:10 C2
08:15 File encryption
```

That timeline is much stronger evidence than individual alerts.

---

## 745. What MITRE tactics could appear?

Potentially:

```text
Initial Access
Execution
Credential Access
Lateral Movement
Command and Control
Impact
```

---

## 746. Why map the attack to MITRE?

It helps communicate:

```text
What happened?
How did attacker operate?
Which techniques were observed?
Where are detection gaps?
```

---

# SECTION L — FINAL L2 SCENARIOS

## 747. Interviewer:

> "EDR says malware was blocked. Close the alert?"

**Answer:**

No.

I would verify:

```text
Was execution prevented?
Was the file removed/quarantined?
Did the process execute?
Did it make network connections?
Was persistence established?
Were credentials exposed?
Are other hosts affected?
```

---

## 748. Interviewer:

> "EDR says malware was blocked but Splunk shows C2 traffic."

**Answer:**

That requires immediate investigation.

Possible explanation:

```text
Another process
+
Earlier execution
+
Second-stage payload
+
False-positive/incorrect correlation
+
Different malware instance
```

I would correlate the timestamps, process, host and destination.

---

## 749. Interviewer:

> "The malware hash appears on 30 machines. What is your first question?"

**Answer:**

> **"Are these machines actually compromised, or is the file legitimately distributed across the environment?"**

Then I'd examine execution and behavior rather than assuming every file presence equals compromise.

---

# 750. FINAL EDR/MALWARE INTERVIEW CHALLENGE

### Interviewer:

> **"You receive an alert for malware execution on an employee workstation. The same workstation then authenticates to three servers and starts making outbound connections to an unknown IP. Walk me through your investigation."**

### Excellent L2 answer:

> "I would treat this as a potentially active compromise and investigate the entire chain rather than only the malware alert."

### Step 1 — Validate malware

```text
Malware alert
↓
Hash
↓
Filename
↓
Path
↓
Process
↓
User
↓
Parent process
```

### Step 2 — Determine execution

```spl
index=endpoint
host="WORKSTATION01"
earliest=-2h
latest=now
| table _time user process_name parent_process_name command_line hash dest_ip dest_port
| sort 0 _time
```

### Step 3 — Investigate authentication

```spl
index=windows EventCode=4624
src_ip="WORKSTATION_IP"
earliest=-2h
latest=now
| stats count by user host
```

### Step 4 — Investigate lateral movement

```text
Workstation
   ↓
Server 1
Server 2
Server 3
```

Determine:

- Account used
    
- Authentication type
    
- Destination systems
    
- Whether access was normal
    

### Step 5 — Investigate C2

```spl
index=firewall
src_ip="WORKSTATION_IP"
earliest=-2h
latest=now
| stats count sum(bytes_out) as bytes_out
        by dest_ip dest_port action
| sort - count
```

### Step 6 — DNS pivot

```spl
index=dns
src_ip="WORKSTATION_IP"
earliest=-2h
latest=now
| stats count by query
| sort - count
```

### Step 7 — Scope

Search for:

```text
Same hash
Same C2 IP
Same domain
Same account
Same process
Same command line
```

### Step 8 — MITRE mapping

Potential techniques could include:

```text
Execution
Credential Access
Lateral Movement
Command and Control
```

depending on evidence.

### Step 9 — Response

> "If the evidence confirms active compromise, I would follow the organization's malware/incident-response playbook and use only the containment actions I'm authorized to perform. I'd escalate appropriately, preserve evidence, document the timeline, and determine whether additional systems or accounts are affected."

---

# 🧠 The L2 Rule You Should Memorize

When you get an **EDR alert**, immediately think:

```text
                EDR ALERT
                    ↓
              WHAT EXECUTED?
                    ↓
               WHO EXECUTED?
                    ↓
              WHERE EXECUTED?
                    ↓
              HOW EXECUTED?
                    ↓
             PARENT PROCESS?
                    ↓
             CHILD PROCESS?
                    ↓
             NETWORK ACTIVITY?
                    ↓
            AUTHENTICATION?
                    ↓
            PERSISTENCE?
                    ↓
          LATERAL MOVEMENT?
                    ↓
                C2?
                    ↓
                SCOPE?
                    ↓
                IMPACT?
                    ↓
             RESPONSE
```

That framework is extremely useful when an interviewer throws a completely unfamiliar malware alert at you.

---
# Splunk SOC Interview — Part 8

## Q751–850 — Phishing, Email Security, Threat Hunting, Alert Triage & Incident Response

This section is especially important because interviewers often give you a **phishing alert** and then keep adding evidence:

> "The user clicked the link. What next?"  
> "They entered credentials. What next?"  
> "There was a successful VPN login. What next?"  
> "Now we see PowerShell. Is it an incident?"

You need to show that you can **follow the attack chain**.

---

# SECTION A — PHISHING FUNDAMENTALS

## 751. What is phishing?

**Answer:**

Phishing is a social-engineering attack where an attacker attempts to trick a victim into revealing information, executing something, transferring money, or performing another malicious action.

---

## 752. What is spear phishing?

Targeted phishing directed at a specific individual or organization.

---

## 753. What is business email compromise?

An attacker abuses or compromises email accounts or impersonates trusted parties to perform fraudulent or unauthorized business actions.

---

## 754. What is credential phishing?

A phishing attack designed to steal usernames, passwords, session information, or other authentication material.

---

## 755. What makes a phishing email suspicious?

Look for combinations such as:

```text
Unusual sender
+
Urgent request
+
Suspicious link
+
Unexpected attachment
+
Impersonation
+
Domain mismatch
+
Credential request
```

---

## 756. Is a suspicious sender address enough?

No.

Sender addresses can be spoofed, compromised, or legitimately delegated.

---

## 757. What should you examine first?

```text
Sender
Recipient
Subject
Timestamp
Reply-To
URLs
Attachments
Authentication results
Headers
```

---

## 758. What are email headers?

Metadata describing how an email was transmitted and authenticated.

---

## 759. Why are headers important?

They can help identify:

- Sending infrastructure
    
- Message path
    
- Authentication results
    
- Message IDs
    
- Originating systems
    
- Routing anomalies
    

---

## 760. What is `Message-ID`?

A unique identifier associated with an email message, useful for correlating the same message across mail-security telemetry.

---

# SECTION B — SPF / DKIM / DMARC

## 761. What is SPF?

**Answer:**

Sender Policy Framework helps domain owners specify which systems are authorized to send email on behalf of their domain.

---

## 762. What is DKIM?

DomainKeys Identified Mail provides cryptographic signing that helps validate message integrity and domain-associated signing.

---

## 763. What is DMARC?

Domain-based Message Authentication, Reporting and Conformance builds on SPF/DKIM and allows domain owners to specify policies and receive reporting.

---

## 764. Does SPF fail mean phishing?

No.

It is an indicator requiring context.

---

## 765. Does SPF pass mean safe?

No.

A malicious sender can use infrastructure authorized to send for a domain they control.

---

## 766. What does DMARC help with?

It can help organizations detect and manage unauthorized use of their domains for email.

---

## 767. Interviewer:

> "The email passes SPF, so it's legitimate. Agree?"

**Answer:**

> "No. SPF only tells me about sender authorization for the relevant domain. I'd also examine DKIM, DMARC alignment, the actual sender domain, URLs, attachments, message content and whether the sending account or infrastructure is trustworthy."

---

## 768. What is domain impersonation?

Using a domain or address designed to look like a trusted organization or person.

---

## 769. What is lookalike-domain phishing?

A domain deliberately made visually similar to a legitimate domain.

Example concept:

```text
legitimate-company.com
vs
legitimate-companny.com
```

---

## 770. Why are users still vulnerable despite email filtering?

Attackers continuously change:

- Domains
    
- Infrastructure
    
- Payloads
    
- URLs
    
- Delivery methods
    
- Social-engineering techniques
    

Security awareness and layered controls remain important.

---

# SECTION C — URL INVESTIGATION

## 771. What do you examine in a phishing URL?

```text
Domain
Subdomain
Path
Redirects
Parameters
Protocol
Reputation
Registration information
First-seen context
```

---

## 772. Is HTTPS proof that a website is safe?

No.

HTTPS protects the connection; it does not prove that the website itself is legitimate.

---

## 773. What is URL reputation?

Information about whether a URL/domain/IP has been associated with malicious activity.

---

## 774. What if the URL reputation is clean?

That doesn't prove safety.

New phishing infrastructure can have no reputation yet.

---

## 775. What should you investigate if a user clicked a URL?

```text
Email
↓
URL
↓
DNS
↓
Proxy
↓
Endpoint
↓
Authentication
↓
File download
↓
Credential submission
```

---

## 776. Find users accessing a suspicious domain.

```spl
index=proxy
dest_domain="suspicious.example"
| stats count by user src_ip
| sort - count
```

---

## 777. Find hosts accessing it.

```spl
index=proxy
dest_domain="suspicious.example"
| stats count by src_ip
| sort - count
```

---

## 778. What if proxy logs don't show the click?

Possible reasons:

```text
DNS-only visibility
Direct connection
Logging gap
Different proxy
Mobile device
Cloud email security
```

Don't assume the click didn't happen.

---

## 779. What should you check in DNS?

```spl
index=dns
query="suspicious.example"
| stats count by src_ip
```

---

## 780. Why correlate email + proxy + DNS?

Because each source answers a different question:

```text
Email → Was it delivered?
Proxy → Was it accessed?
DNS → Was it resolved?
Endpoint → What happened afterward?
```

---

# SECTION D — ATTACHMENT INVESTIGATION

## 781. What makes an attachment suspicious?

Examples:

```text
Unexpected executable
Macro-enabled document
Archive
Password-protected archive
Unusual filename
Double extension
Known malicious hash
```

---

## 782. What is a double extension?

Example:

```text
invoice.pdf.exe
```

The attacker attempts to make the file appear like a PDF.

---

## 783. Is every ZIP attachment malicious?

No.

Archives are widely used legitimately.

---

## 784. What should you investigate?

```text
Filename
Hash
Sender
Recipient
File type
File creation
Process execution
Network activity
```

---

## 785. Scenario: User opens a malicious document.

Potential chain:

```text
Email
 ↓
Attachment
 ↓
Office
 ↓
PowerShell
 ↓
Download
 ↓
Execution
 ↓
C2
```

---

## 786. What should Splunk correlate?

```text
Email telemetry
+
Endpoint process telemetry
+
DNS
+
Proxy
+
Firewall
```

---

## 787. What makes Office execution suspicious?

For example:

```text
Office
 ↓
PowerShell
```

or:

```text
Office
 ↓
cmd
```

or:

```text
Office
 ↓
mshta
```

depending on environment and expected behavior.

---

## 788. What if the user says they didn't open the attachment?

Don't rely solely on the user's statement.

Validate through endpoint telemetry.

---

## 789. What evidence proves execution?

Potentially:

- Process creation
    
- File execution
    
- EDR telemetry
    
- Child process
    
- Network activity
    
- Application logs
    

---

## 790. Why is execution more important than delivery?

Because delivery alone doesn't establish that the payload executed.

---

# SECTION E — CREDENTIAL PHISHING

## 791. Scenario: User clicked a fake Microsoft login page.

What do you investigate?

```text
Email
↓
URL
↓
DNS
↓
Proxy
↓
Authentication logs
↓
VPN
↓
MFA
↓
Cloud identity
```

---

## 792. What if the user entered credentials?

Treat it as potentially compromised credentials.

---

## 793. What would you investigate immediately?

```text
When credentials were entered
↓
Subsequent authentication
↓
Source IP
↓
Geolocation
↓
VPN
↓
MFA
↓
Cloud activity
```

---

## 794. What if the attacker successfully authenticated?

Increase severity and investigate account activity.

---

## 795. What if MFA stopped the attacker?

Still investigate.

The credentials may remain compromised and the attacker may attempt another method.

---

## 796. What is MFA fatigue?

An attacker repeatedly triggers authentication requests hoping the victim eventually approves one.

---

## 797. What telemetry could reveal MFA abuse?

Depending on the identity platform:

```text
Authentication attempts
MFA requests
MFA approvals/denials
Source IP
Device
Location
Timestamp
```

---

## 798. What makes MFA activity suspicious?

```text
Repeated prompts
+
Unusual source
+
Unusual time
+
User reports unexpected prompts
```

---

## 799. What should you do after suspected credential compromise?

Follow the organization's identity-compromise playbook and authorization process.

Potential actions may include:

- Credential reset
    
- Session revocation
    
- Account review
    
- MFA review
    
- Additional monitoring
    

---

## 800. Why investigate sessions as well as passwords?

Because stolen session tokens may allow access without simply replaying the password.

---

# SECTION F — PHISHING ATTACK WALKTHROUGH

## 801. Interviewer:

> "An employee receives a phishing email."

Start with:

```text
Sender
Recipient
Subject
Message-ID
URL
Attachment
Authentication results
```

---

## 802. User clicked the URL.

Next:

```text
Proxy
DNS
Endpoint
```

---

## 803. User entered credentials.

Next:

```text
Authentication
VPN
Cloud identity
MFA
```

---

## 804. Successful login from unusual IP.

Next:

```text
User
Source IP
Device
Application
Geography
Post-authentication activity
```

---

## 805. PowerShell appears.

Now investigate:

```text
Process
Parent
Command line
File
Network
Persistence
```

---

## 806. New server authentication appears.

Investigate:

```text
Lateral movement
Privilege
Destination
Protocol
Account
```

---

## 807. Final attack chain:

```text
Phishing
 ↓
Credential Theft
 ↓
Successful Authentication
 ↓
Endpoint Execution
 ↓
Lateral Movement
 ↓
C2
```

This is now potentially a **multi-stage incident**.

---

# SECTION G — SPLUNK PHISHING QUERIES

## 808. Search email events by sender.

```spl
index=email sender="attacker@example.com"
| table _time sender recipient subject message_id
```

---

## 809. Search by recipient.

```spl
index=email recipient="user@company.com"
| table _time sender recipient subject message_id
```

---

## 810. Search messages containing a suspicious domain.

```spl
index=email
| search url_domain="suspicious.example"
| table _time sender recipient subject url_domain
```

Field names depend on your email integration.

---

## 811. Find how many users received the message.

```spl
index=email subject="Urgent Account Verification"
| stats dc(recipient) as recipients
```

---

## 812. Why is recipient count important?

A phishing campaign targeting 1 user differs from one targeting 500 employees.

---

## 813. Find all recipients.

```spl
index=email subject="Urgent Account Verification"
| stats values(recipient) as recipients
```

---

## 814. Find users who clicked a suspicious domain.

```spl
index=proxy dest_domain="suspicious.example"
| stats values(src_ip) as source_ips by user
```

---

## 815. Find authentication after a phishing click.

Conceptually:

```spl
index=authentication user="victim"
earliest=-2h
latest=+6h
| sort 0 _time
```

Then compare the authentication timeline with the click.

---

# SECTION H — ALERT TRIAGE

## 816. What is alert triage?

**Answer:**

The process of validating, prioritizing and investigating a security alert to determine whether it represents a genuine security issue.

---

## 817. What are your first questions?

```text
What triggered it?
Who?
What host?
When?
Source?
Destination?
Why suspicious?
```

---

## 818. What is alert validation?

Confirming that the underlying telemetry exists and the detection fired for the expected reason.

---

## 819. What is alert enrichment?

Adding context such as:

```text
Asset criticality
User role
Threat intelligence
Known scanner
Geolocation
Historical activity
```

---

## 820. What is alert prioritization?

Determining how urgently an alert should be handled.

---

# SECTION I — INCIDENT SEVERITY

## 821. What determines severity?

Consider:

```text
Confidence
+
Asset criticality
+
User privilege
+
Scope
+
Impact
+
Active attacker behavior
```

---

## 822. Is every malware alert Critical?

No.

Severity depends on context.

---

## 823. Example:

```text
Malware blocked before execution
```

may be very different from:

```text
Malware executed
+
Credential theft
+
C2
+
Lateral movement
```

---

## 824. What is an incident?

A confirmed or suspected security event requiring response according to organizational criteria.

---

## 825. What is an alert?

A notification generated because some condition was detected.

---

## 826. Can multiple alerts represent one incident?

Yes.

---

## 827. Example:

```text
Password spray alert
PowerShell alert
C2 alert
```

could represent one compromised endpoint/account.

---

## 828. Why correlate alerts?

To reconstruct the larger attack.

---

## 829. What is alert grouping?

Grouping related alerts/entities into a common investigative context.

---

## 830. What should determine grouping?

Potentially:

```text
User
Host
Source IP
Destination
Time
Campaign
Indicator
```

---

# SECTION J — INCIDENT RESPONSE

## 831. What are common incident-response phases?

A common model includes:

```text
Preparation
Detection/Analysis
Containment
Eradication
Recovery
Lessons Learned
```

Organizations may use different frameworks.

---

## 832. What is containment?

Actions intended to limit the attacker's ability to continue or expand.

---

## 833. What is eradication?

Removing the cause of compromise.

---

## 834. What is recovery?

Returning systems to a trusted operational state.

---

## 835. What are examples of containment?

Depending on authorization:

```text
Account disablement
Credential reset
Host isolation
Blocking malicious infrastructure
Network containment
```

---

## 836. Should an L1 analyst isolate a machine immediately?

Only if the organization's procedures authorize it or the appropriate escalation path directs it.

---

## 837. Why?

Because containment actions can disrupt business operations and destroy or alter evidence.

---

## 838. What should you preserve?

Relevant:

```text
Logs
Alerts
Timeline
Hashes
Network indicators
Command lines
Process information
Evidence required by IR procedures
```

---

## 839. What is chain of custody?

A documented record of how evidence was collected, handled, transferred and preserved.

---

## 840. Why is evidence integrity important?

Because investigations may need to withstand internal review, legal processes, compliance requirements or forensic analysis.

---

# SECTION K — THREAT HUNTING

## 841. What is threat hunting?

**Answer:**

Proactively searching for malicious or suspicious activity that may not have triggered existing detections.

---

## 842. Detection vs hunting?

```text
Detection
→ System tells you something suspicious happened.

Hunting
→ Analyst actively searches for something suspicious.
```

---

## 843. What is hypothesis-driven hunting?

Example:

> "An attacker may be using PowerShell to execute commands on endpoints."

Then investigate telemetry supporting or disproving that hypothesis.

---

## 844. Example hunt:

```spl
index=endpoint process_name="powershell.exe"
| stats count by host user parent_process_name
| sort - count
```

---

## 845. What do you do after finding an unusual host?

Pivot into:

```text
User
Command line
Parent
Child
Network
Files
Authentication
```

---

## 846. What is threat hunting based on MITRE?

Choose a technique and search for evidence of that technique.

Example:

```text
T1059.001
PowerShell
```

Then hunt for relevant PowerShell telemetry.

---

## 847. What is a hunting lead?

A clue that may justify deeper investigation.

Examples:

```text
Rare process
Rare domain
Unusual login
Unexpected PowerShell
New persistence
```

---

## 848. Is a hunting lead an incident?

No.

It is a starting point.

---

## 849. What is hunting validation?

Determining whether the observed behavior is:

```text
Benign
Suspicious
Malicious
Unknown
```

---

# 850. FINAL PHISHING + SOC INTERVIEW CHALLENGE

### Interviewer:

> **"An employee received a phishing email at 09:00, clicked the link at 09:05, authenticated to VPN from an unusual IP at 09:08, and at 09:12 PowerShell executed on their workstation. What do you do?"**

### Excellent L2 answer:

> "I would treat this as a potentially connected attack chain and investigate the events chronologically rather than handling each alert independently."

### Timeline:

```text
09:00
Phishing email
    ↓
09:05
URL click
    ↓
09:08
VPN authentication
    ↓
09:12
PowerShell
```

### Step 1 — Email

```spl
index=email
recipient="USER"
earliest="09:00"
latest="09:10"
| table _time sender recipient subject url_domain message_id
| sort 0 _time
```

### Step 2 — URL click

```spl
index=proxy
user="USER"
earliest="09:00"
latest="09:15"
| table _time user src_ip dest_domain url
| sort 0 _time
```

### Step 3 — DNS

```spl
index=dns
src_ip="WORKSTATION_IP"
earliest="09:00"
latest="09:20"
| table _time src_ip query response_code
| sort 0 _time
```

### Step 4 — VPN

```spl
index=vpn
user="USER"
earliest="09:00"
latest="09:30"
| table _time user src_ip action device
| sort 0 _time
```

### Step 5 — Endpoint

```spl
index=endpoint
user="USER"
earliest="09:00"
latest="09:30"
| table _time host user process_name parent_process_name command_line dest_ip dest_port
| sort 0 _time
```

### Step 6 — Investigate PowerShell

Ask:

```text
Who launched it?
What was the parent?
What command executed?
Did it download anything?
Did it create a file?
Did it connect externally?
Did it establish persistence?
```

### Step 7 — Scope

Search:

```text
Email indicators
Domain
URL
Source IP
User
Host
Hash
C2 IP
```

across the environment.

### Step 8 — Determine compromise

The combination:

```text
Phishing
+
Click
+
Credential authentication
+
Unusual source
+
PowerShell
```

is significantly more concerning than any single event.

### Step 9 — Response

> "If the evidence confirms compromise, I would follow the organization's credential-compromise and endpoint-incident playbooks, escalate according to severity, and perform only authorized containment actions."

### Step 10 — Document

```text
Initial access
↓
Credential compromise
↓
Authentication
↓
Execution
↓
Network activity
↓
Scope
↓
Impact
↓
Response
```

---

# 🧠 MASTER PHISHING INVESTIGATION FORMULA

Memorize this:

```text
             PHISHING ALERT
                   ↓
              EMAIL HEADER
                   ↓
              URL / FILE
                   ↓
             USER CLICKED?
                   ↓
               DNS
                   ↓
              PROXY
                   ↓
          CREDENTIAL ENTERED?
                   ↓
             AUTH / VPN
                   ↓
              ENDPOINT
                   ↓
             POWERSHELL?
                   ↓
              MALWARE?
                   ↓
                C2?
                   ↓
          LATERAL MOVEMENT?
                   ↓
                SCOPE
                   ↓
                IMPACT
                   ↓
          RESPONSE PLAYBOOK
                   ↓
              DOCUMENT
```

---
# Splunk SOC Interview — Part 9

## Q851–950 — Advanced SPL, `tstats`, CIM, Data Models, ES Troubleshooting & Detection Engineering

Now we're moving into the **advanced L2/L3 territory**. These are the questions that separate someone who has _used Splunk_ from someone who can **troubleshoot, optimize and engineer a SOC detection environment**.

---

# SECTION A — `tstats`

## 851. What is `tstats`?

**Answer:**

`tstats` is a high-performance command used to retrieve statistical information, particularly from indexed fields and accelerated data models.

Example:

```spl
| tstats count
  from datamodel=Authentication.Authentication
  by Authentication.user Authentication.src
```

Exact data-model names and fields depend on the ES/CIM environment.

---

## 852. Why is `tstats` important in Splunk ES?

Because security data models can be accelerated, allowing large-scale security searches to run much faster than repeatedly searching raw events.

---

## 853. `stats` vs `tstats`?

|`stats`|`tstats`|
|---|---|
|Works on search results/events|Works with indexed/data-model structures|
|General purpose|High-performance analytics|
|Often searches raw events first|Can leverage accelerated structures|
|Flexible|More constrained|

---

## 854. Example authentication search with `tstats`.

```spl
| tstats count
  from datamodel=Authentication.Authentication
  by Authentication.user Authentication.src Authentication.dest
```

---

## 855. What is `summariesonly=true`?

It tells certain accelerated-data-model searches to use summary data only.

Example:

```spl
| tstats summariesonly=true count
  from datamodel=Authentication.Authentication
  by Authentication.user
```

---

## 856. What happens if the data model isn't accelerated?

A `tstats`-based detection relying on acceleration may not provide the expected performance/coverage.

---

## 857. Why might `tstats` return fewer results than a raw search?

Potential causes include:

- Data-model constraints
    
- Acceleration window
    
- Incorrect CIM mapping
    
- Missing fields
    
- Summary coverage
    
- Time-range differences
    

---

## 858. Scenario: Raw search returns events, `tstats` returns nothing.

What do you check?

```text
Raw data
↓
CIM mapping
↓
Data model
↓
Acceleration
↓
Time range
↓
Field names
```

---

## 859. Why shouldn't you blindly replace every search with `tstats`?

Because `tstats` is designed around indexed fields and data-model structures and isn't a universal replacement for arbitrary raw-event searches.

---

## 860. What is data-model acceleration?

**Answer:**

A mechanism that precomputes/summarizes information from a data model so supported searches can execute more efficiently.

---

# SECTION B — CIM

## 861. What is CIM?

Common Information Model.

---

## 862. Why is CIM important?

It provides a common structure for security data.

Example concept:

```text
Vendor A:
src_ip

Vendor B:
source_address

        ↓

CIM normalization

        ↓

src
```

The exact normalized field depends on the data model.

---

## 863. Why is normalization important?

It allows one detection to work across multiple data sources.

---

## 864. Example:

Without normalization:

```text
Firewall A → source_ip
Firewall B → src
Firewall C → client_ip
```

With proper normalization:

```text
Detection
   ↓
Normalized field
   ↓
Multiple sources
```

---

## 865. What happens if CIM mapping is wrong?

Detections may:

- Miss events
    
- Produce incorrect results
    
- Generate false positives
    
- Show incomplete dashboards
    

---

## 866. How do you troubleshoot CIM problems?

Check:

```text
Raw event
↓
Sourcetype
↓
Field extraction
↓
CIM field mapping
↓
Data model
↓
Detection
```

---

## 867. Scenario: Firewall data exists but an ES network detection doesn't trigger.

What do you check first?

**Answer:**

I'd verify that the firewall events contain the normalized fields expected by the detection/data model.

---

## 868. Why is field normalization a detection dependency?

Because the detection may search for normalized fields rather than vendor-specific raw fields.

---

## 869. What is a data model?

**Answer:**

A structured representation of related fields and event types used for consistent analytics.

---

## 870. Why are data models useful?

They provide:

- Standardization
    
- Reusable analytics
    
- Acceleration
    
- Consistent security reporting
    

---

# SECTION C — SPL OPTIMIZATION

## 871. Your Splunk search takes 30 minutes. What do you do?

Use this sequence:

```text
1. Narrow time
2. Narrow index
3. Narrow sourcetype
4. Filter early
5. Remove unnecessary fields
6. Avoid expensive commands
7. Consider tstats/data models
8. Test each stage
```

---

## 872. Why filter early?

Because downstream commands then process fewer events.

---

## 873. Bad example:

```spl
index=*
| stats count by user
| search index=windows
```

You're aggregating before appropriately scoping the data.

---

## 874. Better approach:

```spl
index=windows
| stats count by user
```

---

## 875. Why is `index=*` generally undesirable?

It searches unnecessarily broad datasets and can consume substantial resources.

---

## 876. Why can `rex` affect performance?

Regex processing across large event volumes can be expensive.

---

## 877. How can you improve a regex-heavy search?

If the field can be extracted at ingest/search-time appropriately, avoid repeatedly parsing raw text during every investigation.

---

## 878. Why can `transaction` be expensive?

It must correlate events into groups based on transaction criteria and can consume substantial resources.

---

## 879. Why can `join` be expensive?

Joining datasets can require significant processing and may have limitations depending on implementation.

---

## 880. What is the general optimization principle?

> **Reduce the amount of data as early as possible and use the simplest command that answers the question.**

---

# SECTION D — SPL TROUBLESHOOTING

## 881. Search returns zero results. What do you check?

```text
Time range
↓
Index
↓
Sourcetype
↓
Host/source
↓
Field names
↓
Case/value
↓
Data ingestion
```

---

## 882. Search returns events but no fields.

Check:

- Field extraction
    
- Sourcetype
    
- Parsing
    
- Add-on
    
- Field names
    
- Raw event structure
    

---

## 883. Search returns wrong fields.

Check:

```text
props.conf
transforms.conf
TA/add-on
Field extraction
Regex
CIM mapping
```

---

## 884. Search works for yesterday but not today.

Possible causes:

```text
Data stopped
New sourcetype
Parsing changed
Time issue
Forwarder problem
Indexing issue
Source changed
```

---

## 885. Dashboard suddenly shows zero data.

Don't immediately blame the dashboard.

Check:

```text
Dashboard search
↓
Underlying SPL
↓
Data
↓
Time range
↓
Permissions
↓
Lookup/data model
```

---

## 886. Scheduled search stops producing alerts.

Investigate:

```text
Search itself
Scheduler
Permissions
Data availability
Search errors
Throttle/suppression
Notable action
Correlation configuration
```

---

## 887. Why can a valid SPL query produce no detection?

Because the detection depends on:

- Data
    
- Fields
    
- Threshold
    
- Schedule
    
- Time window
    
- Permissions
    
- Actions
    

---

## 888. What if raw data exists but a detection doesn't trigger?

Compare:

```text
Manual search
vs
Detection search
```

Check every condition.

---

## 889. What if manual search works but scheduled search doesn't?

Check:

```text
Time modifiers
Schedule
Permissions
Search mode
Actions
Scheduler workload
```

---

## 890. What is a common time-range mistake?

Using a search window that doesn't align with the scheduled search execution.

---

# SECTION E — CORRELATION SEARCH TROUBLESHOOTING

## 891. What should you check when a correlation search isn't generating notables?

```text
1. Does the search return events?
2. Is the schedule active?
3. Is the threshold met?
4. Is suppression active?
5. Is the notable action configured?
6. Are required fields populated?
7. Are permissions correct?
```

---

## 892. Search returns results but no notable.

Possible issue:

```text
Correlation action
```

rather than search logic.

---

## 893. What is throttling?

A mechanism that can prevent repeated alert generation for similar events according to configured conditions.

---

## 894. Why use throttling?

To prevent alert storms.

---

## 895. What is the danger?

Over-throttling can hide genuine repeated attacks.

---

## 896. Scenario: Detection generates 50 notables for the same host.

What do you consider?

```text
Is this one incident?
Can related alerts be grouped?
Is the detection too noisy?
Should risk aggregation be used?
```

---

## 897. Should you delete the detection?

No.

First understand why it's noisy and whether the detection provides valuable coverage.

---

## 898. What is detection tuning?

Adjusting:

- Thresholds
    
- Filters
    
- Exceptions
    
- Context
    
- Correlation logic
    

to improve useful detections.

---

## 899. What is an exception?

A controlled condition where a known legitimate behavior is handled differently.

---

## 900. What makes an exception dangerous?

An overly broad exception can create a blind spot.

---

# SECTION F — LOOKUPS & MACROS

## 901. What is `inputlookup`?

Reads data from a lookup.

Example:

```spl
| inputlookup asset_lookup.csv
```

---

## 902. Why use `inputlookup`?

For investigations and enrichment using lookup datasets.

---

## 903. What is `outputlookup`?

Writes search results to a lookup.

---

## 904. Why can output lookups be useful?

They can support:

- Enrichment
    
- Reference datasets
    
- Controlled workflows
    

---

## 905. What is a lookup-driven detection?

A detection that uses a reference dataset to determine whether an event matches known entities.

---

## 906. Example:

```spl
index=firewall
| lookup watchlist.csv src_ip OUTPUT threat_level
| where threat_level="high"
```

---

## 907. What is a macro?

**Answer:**

A reusable SPL fragment that can simplify searches and standardize common logic.

---

## 908. Why use macros?

For:

- Reusability
    
- Standardization
    
- Maintainability
    

---

## 909. What is a macro troubleshooting question?

> "The search works when written manually but fails when using the macro."

Check:

```text
Macro definition
Arguments
Permissions
Expanded SPL
Field assumptions
```

---

## 910. Why can macros become dangerous?

A poorly maintained macro can silently affect many detections and searches.

---

# SECTION G — ADVANCED SPL COMMANDS

## 911. What is `append`?

Adds results from another search.

---

## 912. What is `appendcols`?

Appends fields from another search to corresponding rows.

It should be used carefully because row alignment can be problematic.

---

## 913. Difference?

```text
append
→ adds rows

appendcols
→ adds columns
```

---

## 914. What is `fillnull`?

Fills missing/null field values.

Example:

```spl
| fillnull value="unknown" user
```

---

## 915. Why is `fillnull` useful?

It can make results easier to analyze, but don't use it blindly because replacing missing data can hide telemetry-quality problems.

---

## 916. What is `rename`?

Renames fields.

```spl
| rename src_ip as source_ip
```

---

## 917. What is `fields`?

Controls which fields are retained.

```spl
| fields _time user src_ip dest_ip
```

---

## 918. Why use `fields`?

Reducing unnecessary fields can improve clarity and sometimes performance.

---

## 919. What is `mvexpand`?

Expands multivalue fields into separate events/results.

---

## 920. Why are multivalue fields useful?

A single event may contain:

```text
users = alice,bob,charlie
```

and multivalue functions allow you to analyze those values.

---

# SECTION H — TIME FUNCTIONS

## 921. What does `strftime()` do?

Converts epoch time into formatted time.

Example:

```spl
| eval readable=strftime(_time,"%Y-%m-%d %H:%M:%S")
```

---

## 922. What does `strptime()` do?

Converts a formatted time string into epoch time.

---

## 923. What is `relative_time()` useful for?

Calculating relative timestamps.

---

## 924. What is `bin _time` used for?

Creating time buckets.

```spl
| bin _time span=5m
```

---

## 925. Why bucket events?

To identify patterns such as:

```text
Events per 5 minutes
```

rather than examining individual events.

---

# SECTION I — SPL INTERPRETATION

## 926. Interviewer:

> Explain this:

```spl
index=windows EventCode=4625
| stats count by user src_ip
| where count > 20
| sort - count
```

### Answer:

> "It searches failed Windows authentication events, aggregates them by user and source IP, keeps combinations with more than 20 failures, and sorts them by descending count."

---

## 927. Explain:

```spl
index=network
| stats dc(dest_ip) as destinations by src_ip
| where destinations > 100
```

### Answer:

> "It identifies source IPs communicating with more than 100 distinct destination IPs."

Potentially useful for scanning or broad communication hunting.

---

## 928. Explain:

```spl
index=dns
| stats count by src_ip query
| sort - count
```

It counts DNS queries grouped by source IP and queried domain, then sorts from highest to lowest volume.

---

## 929. Explain:

```spl
index=endpoint
| stats values(process_name) by user
```

It shows distinct process names associated with each user.

---

## 930. Explain:

```spl
index=firewall
| stats sum(bytes_out) as total by src_ip
| sort - total
| head 10
```

It identifies the top 10 source IPs by total outbound bytes.

---

# SECTION J — BUILD SPL FROM REQUIREMENTS

## 931. Requirement:

> "Find users with more than 10 failed logins."

```spl
index=windows EventCode=4625
| stats count as failures by user
| where failures > 10
```

---

## 932. Requirement:

> "Find users authenticating from more than five IPs."

```spl
index=windows EventCode=4624
| stats dc(src_ip) as unique_ips by user
| where unique_ips > 5
```

---

## 933. Requirement:

> "Find hosts connecting to more than 50 destinations."

```spl
index=network
| stats dc(dest_ip) as destinations by src_ip
| where destinations > 50
```

---

## 934. Requirement:

> "Find the top outbound data sources."

```spl
index=network
| stats sum(bytes_out) as outbound by src_ip
| sort - outbound
| head 20
```

---

## 935. Requirement:

> "Find suspicious PowerShell launched by Office."

```spl
index=endpoint
process_name="powershell.exe"
parent_process_name IN ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE")
| table _time host user parent_process_name process_name command_line
```

---

# SECTION K — DETECTION ENGINEERING SCENARIOS

## 936. Interviewer:

> "Your detection has too many false positives. What do you do?"

**Answer:**

I would analyze false-positive samples first.

Then identify:

```text
Common users
Common hosts
Known applications
Approved scanners
Expected administrative activity
Time patterns
```

Then improve the detection based on evidence.

---

## 937. Interviewer:

> "How do you know whether tuning improved the detection?"

Compare before and after:

```text
Alert volume
False positives
True positives
Missed attacks
Analyst workload
```

---

## 938. Interviewer:

> "The detection fires only on one vendor's firewall."

What could be wrong?

Possibly the detection depends on vendor-specific fields rather than normalized CIM fields.

---

## 939. Interviewer:

> "How would you make it vendor-neutral?"

Use normalized/CIM-compatible fields where appropriate.

---

## 940. Interviewer:

> "The detection suddenly stopped working after a firewall upgrade."

What do you investigate?

```text
Firewall format
↓
Sourcetype
↓
Field extraction
↓
CIM mapping
↓
Data model
↓
Detection
```

---

# SECTION L — ADVANCED SOC TROUBLESHOOTING

## 941. Scenario:

> Windows logs stopped arriving.

What do you check?

```text
Windows source
↓
Forwarder
↓
Network
↓
Receiving
↓
Indexer
↓
Index
↓
Search
```

---

## 942. Scenario:

> Events exist, but `_time` is wrong.

What do you check?

```text
Timestamp in raw event
↓
props.conf
↓
Timestamp extraction
↓
Timezone
↓
Source format
```

---

## 943. Scenario:

> Events exist, but `src_ip` is missing.

What do you check?

```text
_raw
↓
Field extraction
↓
Sourcetype
↓
TA
↓
Regex
↓
CIM mapping
```

---

## 944. Scenario:

> CIM dashboard is empty but raw logs exist.

Most likely area?

Investigate **normalization/data-model mapping**.

---

## 945. Scenario:

> Raw search works but `tstats` doesn't.

Investigate:

```text
Data model
Acceleration
CIM mapping
Field availability
Time range
```

---

## 946. Scenario:

> Search works manually but scheduled alert doesn't.

Investigate:

```text
Schedule
Time range
Permissions
Scheduler
Search errors
Actions
Suppression
```

---

## 947. Scenario:

> Alert volume suddenly doubles.

What do you investigate?

```text
Data volume
Detection logic
New hosts
New users
Configuration changes
Threshold
Duplicate ingestion
Duplicate alerts
```

---

## 948. Why check duplicate ingestion?

If the same event is indexed multiple times, detection counts can artificially increase.

---

## 949. How do you distinguish attack activity from telemetry duplication?

Compare:

```text
Raw event IDs
Timestamps
Host
Source
Event hashes/identifiers
Ingestion metadata
```

and determine whether the underlying activity itself increased.

---

# 950. FINAL ADVANCED SPLUNK INTERVIEW CHALLENGE

### Interviewer:

> **"Yesterday our Splunk ES brute-force detection generated 200 alerts. Today it generated 2,000. Management wants to know if we're under attack. What do you do?"**

### Don't answer:

> "Yes, we're under attack."

Instead:

> **"I would first determine whether the increase represents a genuine increase in authentication failures or a telemetry/detection issue."**

### Investigation:

```text
                 10× ALERT INCREASE
                         ↓
                CHECK RAW EVENTS
                         ↓
               DID EVENT VOLUME INCREASE?
                    /             \
                  NO               YES
                  ↓                 ↓
            Detection issue      Investigate
                                   ↓
                              Source IPs
                                   ↓
                              Target users
                                   ↓
                              Target hosts
                                   ↓
                         Failed vs successful
                                   ↓
                         Known scanners?
                                   ↓
                         Legitimate change?
                                   ↓
                         Attack pattern?
```

### First SPL:

```spl
index=windows EventCode=4625
earliest=-48h
latest=now
| timechart span=1h count
```

Compare today versus yesterday.

### Then:

```spl
index=windows EventCode=4625
earliest=-24h
latest=now
| stats count as failures
        dc(user) as users
        dc(src_ip) as sources
        by src_ip
| sort - failures
```

### Then ask:

```text
Did failures increase?
Did unique sources increase?
Did unique users increase?
Did the same source target many users?
Were there successful logins?
```

### If successful logins exist:

```spl
index=windows
(EventCode=4624 OR EventCode=4625)
earliest=-24h
latest=now
| stats
    count(eval(EventCode=4625)) as failures
    count(eval(EventCode=4624)) as successes
    by src_ip user
| where failures > 20 AND successes > 0
| sort - failures
```

### Then investigate:

```text
Authentication
↓
Endpoint
↓
PowerShell
↓
Network
↓
DNS
↓
Privilege
↓
Lateral movement
```

### Final interview answer:

> **"I would first separate a detection-volume problem from a security-event-volume problem. If the underlying failed-authentication volume also increased, I'd determine whether it's a genuine attack, legitimate operational change, or scanning. If successful authentication and post-authentication activity are present, I'd escalate the investigation because that would increase the likelihood of actual compromise."**

---

# 🧠 PART 9 MASTER CHEAT SHEET

### If Splunk is slow:

```text
TIME
 ↓
INDEX
 ↓
SOURCETYPE
 ↓
FILTER
 ↓
FIELDS
 ↓
EXPENSIVE COMMANDS
 ↓
DATA MODEL / TSTATS
```

### If detection doesn't fire:

```text
DATA?
 ↓
FIELDS?
 ↓
CIM?
 ↓
QUERY?
 ↓
THRESHOLD?
 ↓
SCHEDULE?
 ↓
ACTION?
 ↓
SUPPRESSION?
```

### If ES dashboard is empty:

```text
RAW DATA
 ↓
FIELD EXTRACTION
 ↓
CIM
 ↓
DATA MODEL
 ↓
ACCELERATION
 ↓
DASHBOARD SEARCH
```

### If alert volume suddenly increases:

```text
REAL ATTACK?
       OR
DATA DUPLICATION?
       OR
CONFIG CHANGE?
       OR
DETECTION CHANGE?
       OR
LEGITIMATE ACTIVITY?
```

---
# Splunk SOC Analyst L1/L2 Interview — PART 10

## Q951–1000 — Final 50 Hard Questions

This is the **final 50-question interview round**. These are designed to test whether you can actually **think like a SOC analyst**, not just remember Splunk commands.

---

# 🔥 SECTION A — REAL-WORLD SOC SCENARIOS

### 951. You receive a critical alert. What do you do first?

**Answer:**

> "I validate the alert before assuming compromise. I identify the affected user, host, source IP, destination, timestamp and triggering behavior, then correlate supporting telemetry."

---

### 952. One failed login occurred from a foreign country. Is it an attack?

**Answer:**

No.

One failed login is an indicator, not proof.

I would check:

- User
    
- Source IP reputation
    
- VPN usage
    
- Geo-location
    
- Historical behavior
    
- Successful authentication
    
- MFA
    
- Endpoint activity
    

---

### 953. 1,000 failed logins occur against one account. What does it suggest?

Potential:

- Brute force
    
- Credential attack
    
- Misconfigured application
    
- Password manager issue
    
- Legitimate automation
    

Investigate the source and subsequent successful authentication.

---

### 954. One IP attacks 100 users. What could this be?

Likely:

**Password spraying**

because one source is attempting authentication against many accounts.

---

### 955. One account receives 100 password attempts from one IP.

Potential:

**Brute-force attack.**

---

### 956. You see:

```text
4625
4625
4625
4624
4688
PowerShell
```

What does this suggest?

A possible authentication attack followed by successful access and process execution.

I would investigate the source, user, host, PowerShell command line and subsequent network activity.

---

### 957. You see:

```text
Phishing email
↓
User clicks URL
↓
DNS query
↓
Proxy connection
↓
PowerShell
↓
C2
```

What is your assessment?

This is a strong multi-stage attack chain.

Potentially:

```text
Initial Access
↓
Execution
↓
Command and Control
```

I would investigate the endpoint and scope immediately.

---

### 958. How do you prove that phishing resulted in compromise?

Don't rely on the email alone.

Correlate:

```text
Email
↓
URL click
↓
DNS
↓
Proxy
↓
Endpoint process
↓
Network connection
↓
Credential/authentication activity
```

---

### 959. A malicious hash is detected on one endpoint. What next?

Determine:

- Is it running?
    
- Where did it come from?
    
- Parent process
    
- User
    
- Network connections
    
- Other endpoints
    
- Persistence
    
- Execution time
    

Then determine containment requirements.

---

### 960. Malware exists on 50 endpoints. What changes?

The incident becomes significantly broader.

I would:

1. Determine common infection vector.
    
2. Identify affected systems.
    
3. Identify patient zero where possible.
    
4. Search for common IOCs.
    
5. Determine lateral movement.
    
6. Contain affected systems according to the IR playbook.
    
7. Escalate appropriately.
    

---

# 🧠 SECTION B — L2 INVESTIGATION THINKING

### 961. What separates an L1 analyst from an L2 analyst?

**L1:**

- Alert triage
    
- Validation
    
- Basic enrichment
    
- Escalation
    

**L2:**

- Deeper investigation
    
- Correlation
    
- Threat hunting
    
- Scope analysis
    
- Detection tuning
    
- Root-cause analysis
    
- Incident coordination
    

---

### 962. An L1 escalates an alert to you. What do you expect?

I expect:

- Alert reason
    
- Time
    
- User
    
- Host
    
- Source/destination
    
- Evidence
    
- Initial analysis
    
- Queries/results
    
- Reason for escalation
    

---

### 963. What if the L1 escalation is incomplete?

I'd clarify the missing information rather than blindly continuing with assumptions.

---

### 964. How do you build an investigation timeline?

Start with the earliest known suspicious event and correlate:

```text
Initial activity
↓
Authentication
↓
Execution
↓
Persistence
↓
Privilege escalation
↓
Lateral movement
↓
C2
↓
Exfiltration
```

Not every incident contains every phase.

---

### 965. What is patient zero?

The earliest identified compromised or initially affected system/account in an incident.

---

### 966. How do you identify patient zero?

Look for the earliest credible evidence:

- First malicious email
    
- First suspicious process
    
- First malicious connection
    
- First affected endpoint
    
- First compromised account
    

---

### 967. What does "scope" mean?

The total set of potentially affected:

- Users
    
- Hosts
    
- Accounts
    
- IPs
    
- Applications
    
- Data
    

---

### 968. Why is scope important?

Because responding to one host while ignoring other compromised systems can allow the attacker to persist.

---

### 969. What is root cause?

The underlying reason the incident occurred.

Example:

```text
Phishing
↓
Credential theft
↓
No MFA
↓
Account compromise
```

The phishing email may be the initial vector, while lack of MFA may be an important contributing control weakness.

---

### 970. What is blast radius?

The potential extent of impact from an incident.

---

# ⚔️ SECTION C — ADVANCED ATTACK CHAIN

### 971. Scenario:

You see:

```text
Email attachment
↓
WINWORD.EXE
↓
PowerShell
↓
Encoded command
↓
External IP
↓
Scheduled task
```

What do you suspect?

A likely multi-stage malware execution and persistence chain.

Potential ATT&CK areas:

- Phishing
    
- User Execution
    
- PowerShell
    
- Command and Control
    
- Scheduled Task/Job
    

---

### 972. What do you investigate next?

Endpoint telemetry.

Especially:

```text
Command line
Parent process
Child processes
File creation
Network connections
Persistence
User
Host
```

---

### 973. PowerShell is not automatically malicious. Explain.

PowerShell is a legitimate administrative tool.

The context matters:

```text
Who?
What command?
Parent process?
Encoded?
Downloaded content?
Network connection?
Expected admin activity?
```

---

### 974. What is LOLBin abuse?

Using legitimate operating-system utilities for malicious purposes.

Examples may include:

- `rundll32`
    
- `regsvr32`
    
- `mshta`
    
- `certutil`
    
- `bitsadmin`
    

The exact detection should consider command-line context rather than simply flagging the executable name.

---

### 975. An attacker uses a legitimate administrator account. Why is that difficult?

Because the authentication itself may look legitimate.

You need behavioral context:

```text
Source
Time
Host
User behavior
Command execution
Privilege use
Location
Network activity
```

---

# 🔎 SECTION D — THREAT HUNTING

### 976. What is threat hunting?

Proactively searching for malicious activity that may not have generated an alert.

---

### 977. Detection vs hunting?

|Detection|Hunting|
|---|---|
|Usually triggered automatically|Analyst-driven|
|Known suspicious pattern|Hypothesis-driven|
|Alert-based|Search-based|
|Continuous/ scheduled|Proactive investigation|

---

### 978. Give a hunting hypothesis.

> "I suspect an attacker may be using PowerShell to execute commands on endpoints."

Then investigate:

```spl
index=endpoint process_name="powershell.exe"
| stats count by host user parent_process_name
| sort - count
```

---

### 979. How do you hunt for C2?

Look for:

- Repeated outbound connections
    
- Periodic timing
    
- Rare destinations
    
- Suspicious domains
    
- Unusual ports
    
- Beacon-like behavior
    
- Endpoint/network correlation
    

---

### 980. How do you hunt for DNS tunneling?

Look for:

- High query volume
    
- Long/random subdomains
    
- High entropy
    
- Many unique subdomains
    
- Repeated queries
    
- Unusual TXT activity
    
- Rare domains
    

No single indicator proves DNS tunneling.

---

# 🛠️ SECTION E — SPL INTERVIEW RAPID FIRE

### 981. How do you count events?

```spl
| stats count
```

---

### 982. Count events by user?

```spl
| stats count by user
```

---

### 983. Count unique users?

```spl
| stats dc(user)
```

---

### 984. Top 10 users by event volume?

```spl
| stats count by user
| sort - count
| head 10
```

---

### 985. Search failed Windows logins?

```spl
index=windows EventCode=4625
```

---

### 986. Find successful logins?

```spl
index=windows EventCode=4624
```

---

### 987. Find PowerShell?

```spl
index=endpoint process_name="powershell.exe"
```

---

### 988. Find multiple destinations?

```spl
index=network
| stats dc(dest_ip) as destinations by src_ip
| sort - destinations
```

---

### 989. Create a 5-minute time bucket?

```spl
| bin _time span=5m
```

---

### 990. Show events as a time chart?

```spl
| timechart span=1h count
```

---

# 🎯 SECTION F — DIFFICULT INTERVIEWER FOLLOW-UPS

### 991. Interviewer:

> "You said this is malicious. Prove it."

**Best answer:**

> "I wouldn't classify it as malicious based on a single indicator. I'd show the correlated evidence: the initiating activity, affected identity or host, execution behavior, network communication, and any persistence or follow-on activity. I'd also rule out documented legitimate activity."

---

### 992. Interviewer:

> "What if you don't have enough logs?"

**Answer:**

> "I'd identify the telemetry gap, use the available sources to establish what I can, avoid overclaiming, and escalate the visibility issue. I'd also recommend improving telemetry coverage if the missing data materially affects detection or investigation."

---

### 993. Interviewer:

> "What if Splunk says nothing happened?"

**Answer:**

> "I'd distinguish between 'no malicious activity occurred' and 'Splunk has no evidence.' I'd verify telemetry coverage before concluding that the activity didn't happen."

🔥 **This is a very strong L2 answer.**

---

### 994. Interviewer:

> "Your detection says an attack occurred. Endpoint says nothing happened. What do you trust?"

**Answer:**

> "Neither source automatically wins. I'd validate both telemetry sources, compare timestamps and entities, inspect raw events, determine whether the endpoint has appropriate visibility, and look for independent corroborating evidence."

---

### 995. Interviewer:

> "You have 10,000 alerts. What do you investigate first?"

**Answer:**

Prioritize based on:

```text
Severity
↓
Confidence
↓
Asset criticality
↓
User privilege
↓
Evidence of successful compromise
↓
Potential business impact
```

---

### 996. Interviewer:

> "What's more important: severity or confidence?"

**Answer:**

Both matter.

A critical-severity alert with extremely low confidence may require different handling than a high-confidence detection of active compromise.

I would combine:

```text
Severity
+
Confidence
+
Asset criticality
+
Evidence
+
Impact
```

---

### 997. Interviewer:

> "What would make you escalate immediately?"

Examples:

- Confirmed ransomware
    
- Active C2
    
- Domain admin compromise
    
- Confirmed credential theft
    
- Widespread malware
    
- Data exfiltration
    
- Critical infrastructure compromise
    
- Active attacker behavior
    

Follow the organization's escalation and incident-response procedures.

---

### 998. Interviewer:

> "What do you document in an incident?"

```text
Alert
↓
Initial evidence
↓
Queries
↓
Timeline
↓
Entities
↓
Scope
↓
MITRE mapping
↓
Actions
↓
Containment
↓
Root cause
↓
Impact
↓
Lessons learned
```

---

### 999. Interviewer:

> "Give me your complete methodology for investigating a suspicious alert."

### ⭐ Memorize this:

> **"First, I validate the alert and understand exactly what triggered it. Then I identify the key entities such as user, host, source IP, destination IP, process and timestamp. I establish the investigation window and build a timeline. I pivot across authentication, endpoint, DNS, firewall, proxy and other relevant telemetry. I determine whether the behavior is legitimate, suspicious or confirmed malicious, then assess scope, impact and potential persistence or lateral movement. Where appropriate, I map the behavior to MITRE ATT&CK. If compromise is confirmed, I follow the organization's incident-response playbook and escalate or contain according to my authorization. Finally, I document the evidence, queries, timeline, conclusion and detection-tuning opportunities."**

---

# 🏆 1000. FINAL MASTER INTERVIEW QUESTION

### Interviewer:

> **"Imagine you're the only SOC analyst on shift. Splunk generates an alert for suspicious PowerShell on a domain controller. What do you do?"**

### ⭐⭐⭐ Strong L2 Answer

> **"I would treat this as high priority because the affected system is a domain controller. First I'd validate the alert and identify the user, host, timestamp, parent process, command line and PowerShell activity. I'd determine whether the PowerShell execution was expected administrative activity."**

> **"Then I'd correlate the endpoint event with authentication logs, privilege events, process creation, network connections, DNS and other available telemetry. I'd look for indicators of credential access, privilege escalation, lateral movement and command-and-control activity."**

> **"I'd build a timeline and determine whether this is an isolated execution or part of a broader attack chain. I'd also search across the environment for the same command line, hash, user, source IP, destination or behavior to establish scope."**

> **"If malicious activity is confirmed, I'd follow the organization's incident-response procedure and my authorization level for containment and escalation. Because it's a domain controller, I'd involve the appropriate incident-response or identity/infrastructure teams rather than taking unauthorized destructive action."**

> **"Finally, I'd document the evidence, queries, timeline, affected entities, MITRE ATT&CK techniques where applicable, actions taken and recommendations for detection improvement."**

### Why this is a strong answer

It demonstrates:

```text
Alert validation
      ↓
Critical asset awareness
      ↓
Evidence collection
      ↓
Correlation
      ↓
Timeline
      ↓
Threat hunting
      ↓
Scope determination
      ↓
MITRE
      ↓
Incident response
      ↓
Escalation
      ↓
Documentation
      ↓
Detection improvement
```

---
## 🔥 The 10 answers I'd memorize first

If you don't have time to memorize all 1,000, master these concepts:

1. **Alert triage methodology**
    
2. **Failed login → successful login → endpoint execution**
    
3. **Phishing → endpoint → C2**
    
4. **Scope determination**
    
5. **Timeline construction**
    
6. **False-positive tuning**
    
7. **CIM/data-model troubleshooting**
    
8. **`stats` vs `tstats`**
    
9. **"No logs ≠ no attack"**
    
10. **Domain-controller PowerShell investigation**
    

### Your core L2 sentence

> **"I don't make a conclusion from a single indicator; I correlate independent telemetry, establish a timeline, determine scope and impact, validate the hypothesis, and then follow the appropriate incident-response procedure."**

That sentence captures the **L2 SOC mindset** better than memorizing hundreds of isolated answers.

----
