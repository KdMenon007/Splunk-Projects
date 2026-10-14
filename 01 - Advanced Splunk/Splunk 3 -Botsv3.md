
## ☁️ AWS + Endpoint + SOC Investigation 

---

# 🔰 0. CORE REALITY (Read this twice)

> Cloud attacks don’t look like hacking.  
> They look like **normal API calls done at the wrong time, by the wrong user, in the wrong way**.

---

## 🧩 Data Sources in This Lab

|Source Type|What it Gives|
|---|---|
|`aws:cloudtrail`|AWS API activity|
|`aws:s3:accesslogs`|S3 object access|
|`winhostmon`|Windows host info|
|`hardware`|system hardware|

---

## 🧠 Investigation Flow (Golden Model)

```
Alert → Triage → Identify User → Trace Actions → Validate Security → Check Impact → Build Timeline → Confirm Compromise
```

---

# ☁️ 1. IAM USER ACTIVITY (ENTRY POINT)

---

## 🎯 Goal

Identify **all users interacting with AWS**

---

## 🔍 Query

```spl
index=botsv3 sourcetype=aws:cloudtrail
| stats count by user
```

---

## 🧠 What This Means

You are building:  
👉 **Who is active in the environment**

---

## 🔥 Advanced Version

```spl
index=botsv3 sourcetype=aws:cloudtrail
| stats count by user, eventName, eventSource
| sort -count
```

---

## 🧠 Analyst Thinking

Ask:

- Which user does **unusual actions**?
    
- Which user interacts with **multiple services**?
    

---

## 🚨 Known Users

- bstoll
    
- btun
    
- splunk_access
    
- web_admin
    

---

## ⚠️ Red Flags

- IAM user creating users
    
- IAM user modifying permissions
    
- High diversity of actions
    

---

# 🔐 2. DETECTING NO-MFA ACTIVITY

---

## 🎯 Goal

Find **AWS actions without MFA**

---

## 🔍 Core Query

```spl
index=botsv3 sourcetype=aws:cloudtrail
NOT tag::eventtype=authentication
userIdentity.sessionContext.attributes.mfaAuthenticated=false
```

---

## 🧠 Why This Matters

MFA = last defense layer

Without MFA:  
👉 stolen credentials = full access

---

## 🔥 Advanced Detection

```spl
index=botsv3 sourcetype=aws:cloudtrail
userIdentity.sessionContext.attributes.mfaAuthenticated=false
| stats count by user, eventName, sourceIPAddress
```

---

## 🚨 High-Risk Actions Without MFA

- PutBucketAcl
    
- CreateUser
    
- DeleteTrail
    
- AttachRolePolicy
    

---

## 🧠 SOC Insight

> No MFA + Sensitive API call = 🚨 Possible account takeover

---

# 🖥️ 3. INFRASTRUCTURE BASELINING (HARDWARE)

---

## 🎯 Goal

Understand system baseline

---

## 🔍 Query

```spl
index=botsv3 sourcetype=hardware
| table host, CPU_TYPE
```

---

## ✅ Result

- CPU: **E5-2676**
    

---

## 🧠 Why This Matters

Baseline helps detect:

- rogue systems
    
- attacker infrastructure
    
- anomalies
    

---

## 🔥 Detection Query

```spl
index=botsv3 sourcetype=hardware
| stats values(CPU_TYPE) by host
```

---

# 🚨 4. S3 BUCKET EXPOSURE (CRITICAL EVENT)

---

## 🎯 Goal

Detect public bucket exposure

---

## 🔍 Query

```spl
index=botsv3 sourcetype=aws:cloudtrail
eventName=PutBucketAcl
```

---

## 🧠 What Happens Here

`PutBucketAcl` changes:  
👉 bucket permissions

---

## 🔥 Critical Indicator

Search inside:

```json
AllUsers
```

👉 Means:

> Public internet access enabled

---

## 🔍 Enhanced Query

```spl
index=botsv3 sourcetype=aws:cloudtrail
eventName=PutBucketAcl
| search "AllUsers"
```

---

## ✅ Event ID

- ab45689d-69cd-41e7-8705-5350402cf7ac
    

---

# 👤 5. WHO CAUSED IT (IDENTITY ANALYSIS)

---

## 🔍 Query

```spl
index=botsv3 sourcetype=aws:cloudtrail
eventName=PutBucketAcl
| table _time, user, sourceIPAddress
```

---

## ✅ Answer

- **bstoll**
    

---

## 🧠 Analyst Thinking

Ask:

- Was this normal admin activity?
    
- Was MFA used?
    
- Is IP trusted?
    

---

## 🔥 Behavior Profiling

```spl
index=botsv3 sourcetype=aws:cloudtrail
user=bstoll
| stats count by eventName
```

---

# 🪣 6. WHICH BUCKET WAS EXPOSED

---

## 🔍 Query

```spl
index=botsv3 sourcetype=aws:cloudtrail
eventName=PutBucketAcl
| table bucket_name
```

---

## ✅ Answer

- **frothlywebcode**
    

---

## 🧠 Why Important

Now you know:  
👉 what data is at risk

---

# 📥 7. WAS THE BUCKET EXPLOITED?

---

## 🎯 Goal

Check attacker interaction

---

## 🔍 Query

```spl
index=botsv3 sourcetype=aws:s3:accesslogs
bucket_name=frothlywebcode
| stats count by operation
```

---

## 🧠 Operation Meaning

|Operation|Meaning|
|---|---|
|GET|download|
|PUT|upload|

---

## 🔥 Focus on uploads

```spl
index=botsv3 sourcetype=aws:s3:accesslogs
bucket_name=frothlywebcode
operation=REST.PUT.OBJECT
| table _time, requester, object
```

---

## ✅ Result

- **OPEN_BUCKET_PLEASE_FIX.txt**
    

---

## 🧠 Analyst Insight

This is:  
👉 attacker validation file

---

## ⚠️ Meaning

- Bucket exposed
    
- External entity accessed
    
- System is compromised
    

---

# 🖥️ 8. ENDPOINT ANOMALY DETECTION

---

## 🎯 Goal

Find abnormal host

---

## 🔍 Query

```spl
index=botsv3 sourcetype=winhostmon
| dedup OS, host
| table OS, host
```

---

## ✅ Result

- **BSTOLL-L.froth.ly**
    

---

## 🧠 Why Important

Outlier host = potential:

- compromised machine
    
- attacker foothold
    

---

## 🔥 Deep Pivot

```spl
index=botsv3 host=BSTOLL-L
| stats count by sourcetype
```

---

# 🧠 9. BUILDING THE ATTACK TIMELINE

---

## 🔍 Unified Query

```spl
index=botsv3 (sourcetype=aws:cloudtrail OR sourcetype=aws:s3:accesslogs)
| sort _time
| table _time, user, eventName, bucket_name, operation, sourceIPAddress
```

---

## 🧠 What You See

1. User performs AWS actions
    
2. Bucket made public
    
3. External interaction
    
4. File uploaded
    

---

## 🔥 This is your evidence chain

---

# 🚨 10. INCIDENT CLASSIFICATION

---

## 🧩 Signals Observed

|Indicator|Meaning|
|---|---|
|No MFA|weak security|
|PutBucketAcl|exposure|
|External upload|confirmed access|
|IAM activity|possible misuse|
|Host anomaly|endpoint risk|

---

## 🎯 Final Verdict

👉 **Account Compromise + Misconfiguration Exploited**

---

# 🧠 11. RESPONSE ACTIONS (REAL SOC)

---

## 🚨 Immediate

- Disable user `bstoll`
    
- Enable MFA
    
- Lock S3 bucket
    
- Rotate credentials
    

---

## 🔍 Investigation

```spl
index=botsv3 sourcetype=aws:cloudtrail
eventName IN ("CreateUser","AttachRolePolicy","DeleteTrail")
```

---

## 🧠 Why

Attackers often:

- create backdoor users
    
- escalate privileges
    
- disable logging
    

---

# 🔥 12. DETECTION ENGINEERING (ELITE LEVEL)

---

## 🚨 Detection Rule 1 — No MFA + Sensitive Action

```spl
index=botsv3 sourcetype=aws:cloudtrail
userIdentity.sessionContext.attributes.mfaAuthenticated=false
eventName IN ("PutBucketAcl","CreateUser","DeleteBucket")
```

---

## 🚨 Detection Rule 2 — Public Bucket Exposure

```spl
index=botsv3 sourcetype=aws:cloudtrail
eventName=PutBucketAcl
| search "AllUsers"
```

---

## 🚨 Detection Rule 3 — Suspicious Upload

```spl
index=botsv3 sourcetype=aws:s3:accesslogs
operation=REST.PUT.OBJECT
```

---

## 🚨 Detection Rule 4 — Unusual IAM Behavior

```spl
index=botsv3 sourcetype=aws:cloudtrail
| stats dc(eventName) as unique_actions by user
| where unique_actions > 10
```

---

