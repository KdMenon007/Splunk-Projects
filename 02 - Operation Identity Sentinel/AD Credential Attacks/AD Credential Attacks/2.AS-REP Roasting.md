# 🔥 AS-REP Roasting — SOC L1/L2 Cheat Sheet

## 1️⃣ Core Difference


## Kerberoasting vs AS-REP Roasting

| Feature                      | Kerberoasting                     | AS-REP Roasting                                   |
| ---------------------------- | --------------------------------- | ------------------------------------------------- |
| **Target**                   | Service accounts with **SPNs**    | User accounts with **preauthentication disabled** |
| **SPN required**             | ✅ Yes                             | ❌ No                                              |
| **Valid domain credentials** | Usually required                  | ❌ Not necessarily                                 |
| **Request**                  | TGS                               | TGT / AS-REP                                      |
| **Event**                    | **4769**                          | **4768**                                          |
| **Main signal**              | `0x17` RC4 + unusual SPN activity | `Pre_Authentication_Type=0`                       |
| **Offline cracking**         | ✅ Yes                             | ✅ Yes                                             |
|                              |                                   |                                                   |
### 🧠 Memorize

> **Kerberoasting = SPN → TGS → 4769**  
> **AS-REP Roasting = No Preauth → TGT → 4768**

---

# 2️⃣ Normal Kerberos Authentication

Normally the user must prove they know their password **before receiving a TGT**.

```text
User
 ↓
AS-REQ + encrypted timestamp
 ↓
Domain Controller
 ↓
Verify timestamp
 ↓
TGT issued
 ↓
TGS request
 ↓
Service access
```

### Events

```text
4768 → TGT request
4769 → TGS request
4624 → Successful logon
```

### Normal preauthentication

```text
Pre_Authentication_Type=2
```

Usually with:

```text
Ticket_Encryption_Type=0x12
```

= AES-256.

---

# 3️⃣ What Causes AS-REP Roasting?

The account has:

```text
DONT_REQUIRE_PREAUTH
```

This means the DC doesn't require the normal preauthentication proof.

```text
Attacker
 ↓
Requests TGT
 ↓
DC skips preauthentication
 ↓
AS-REP returned
 ↓
Encrypted material
 ↓
Offline password cracking
```

### Critical point

The attacker can potentially perform this **without already having a valid domain account**.

They need to identify an account for which preauthentication is disabled.

---

# 4️⃣ Why Does This Happen?

Usually due to:

- Legacy applications.
    
- Old ERP systems.
    
- Payroll applications.
    
- Application compatibility requirements.
    
- Poorly documented AD configurations.
    
- Administrators disabling preauthentication and forgetting about it.
    

### Root cause

```text
Legacy requirement
      ↓
Preauth disabled
      ↓
Account becomes roastable
```

---

# 5️⃣ Main Detection Event

### Event 4768

**Kerberos Authentication Service / TGT Request**

Look at:

```text
Pre_Authentication_Type
```

### Values

```text
2  → Normal encrypted-timestamp preauthentication
0  → No preauthentication 🚨
15 → Certificate-based authentication may appear
```

---

# 6️⃣ Main AS-REP Signal

```text
EventCode=4768
+
Pre_Authentication_Type=0
```

If you also see:

```text
Ticket_Encryption_Type=0x17
```

the suspicion becomes stronger in this lab context.

---

# 7️⃣ First Splunk Query

```spl
index=task3 EventCode=4768
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
| sort _time
```

### Purpose

First understand **normal Kerberos traffic**.

Don't immediately hunt for the anomaly.

---

# 8️⃣ Isolate AS-REP Candidates

```spl
index=task3 EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
```

This gives you:

- Time
    
- Account
    
- Preauthentication type
    
- Encryption
    
- Source IP
    

---

# 9️⃣ How to Interpret the Result

Example:

```text
Account: svc_legacy
PreAuth: 0
Encryption: 0x17
Client: 10.5.90.25
```

Meaning:

> `svc_legacy` has preauthentication disabled, and someone requested a TGT for it.

This is **suspicious**, but don't immediately say:

> "Confirmed AS-REP Roasting."

You still investigate the surrounding behavior.

---

# 🔎 10️⃣ Follow-Up Investigation

Check whether the account subsequently generated:

- `4769` → TGS request
    
- `4624` → Successful logon
    

Query:

```spl
index=task3 (EventCode=4624 OR EventCode=4769)
| search Account_Name="{ACCOUNT_NAME}"
| table _time, EventCode, Account_Name, Client_Address
```

---

# 1️⃣1️⃣ Suspicious Pattern

```text
4768
PreAuth = 0
     ↓
No 4769
     ↓
No 4624
```

This suggests:

> The TGT may have been requested specifically to obtain crackable material rather than to access a service.

### ⚠️ But NOT definitive

A legitimate application could:

- Fail before requesting a TGS.
    
- Use cached tickets.
    
- Fail authentication.
    
- Stop before completing the expected Kerberos sequence.
    

So:

> **Absence of 4769/4624 increases suspicion but does not prove malicious activity.**

---

# 🔥 12️⃣ Stronger Detection Combination

Think:

```text
4768
+
PreAuth = 0
+
RC4 = 0x17
+
Unusual source
+
No expected follow-up
=
HIGHER AS-REP ROASTING SUSPICION
```

---

# 13️⃣ Kerberoasting vs AS-REP Roasting

### Kerberoasting

```text
SPN
 ↓
TGS
 ↓
4769
 ↓
Offline crack
```

### AS-REP Roasting

```text
DONT_REQUIRE_PREAUTH
 ↓
TGT / AS-REP
 ↓
4768
 ↓
Offline crack
```

---

# 🧠 14️⃣ Ultimate Memory Table

|Concept|Remember|
|---|---|
|AS-REP target|Preauth-disabled account|
|AD flag|`DONT_REQUIRE_PREAUTH`|
|Main event|**4768**|
|Main field|`Pre_Authentication_Type`|
|Suspicious value|**0**|
|Normal value|**2**|
|Common encryption|AES `0x12`|
|RC4|`0x17`|
|SPN required?|❌|
|Valid domain account required?|❌ Not necessarily|
|Attack method|Offline cracking|
|Follow-up events|Often no 4769/4624 in pure hash-harvesting scenario|

---

# 🎯 15️⃣ Interview Answer

> **AS-REP Roasting targets Active Directory accounts that have Kerberos preauthentication disabled. Unlike Kerberoasting, it doesn't require an SPN and an attacker doesn't necessarily need valid domain credentials. The attacker requests a TGT, receives an AS-REP encrypted using material derived from the account's password, and attempts to crack it offline. From a SOC perspective, Event 4768 with `Pre_Authentication_Type=0` is the primary detection signal. I would then investigate the requesting source, account, encryption type, and whether subsequent 4769 or 4624 activity occurred.**

### ⚡ One-liner

> **4768 + PreAuth 0 = investigate AS-REP Roasting.**