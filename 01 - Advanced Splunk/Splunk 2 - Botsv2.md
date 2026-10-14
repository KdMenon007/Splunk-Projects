
## 🕵️‍♀️ Investigation Notes (Explained Like a Real Analyst)

---

# 🔰 0. The Mindset (This is everything)

Before touching Splunk, understand this:

> Logs don’t give answers. They give fragments.

Your job is to:

- Connect fragments
    
- Follow behavior, not keywords
    
- Pivot intelligently
    

### 🧩 The Golden Pivot Chain

```
User → IP → Web Traffic → Email → Files → DNS → Persistence
```

If you get stuck, you didn’t pivot enough.

---

# 🕵️ 100 SERIES — AMBER TURING

---

## 🎯 What are we trying to do?

Amber is:

- An insider (employee)
    
- Looking at a competitor
    
- Sending emails externally
    

👉 This screams:

- Data exfiltration
    
- Insider threat
    

---

## 🔍 Step 1: Find Amber’s IP

Why?  
Because everything in logs is tied to IP, not names.

### Query:

```spl
index="botsv2" sourcetype="pan:traffic" amber
```

### 🧠 Logic:

- Palo Alto firewall logs = network visibility
    
- We search "amber" to find events tied to her
    

### ✅ Result:

- IP = **10.0.2.101**
    

👉 Now we have identity → machine mapping.

---

## 🌐 Step 2: What website did she visit?

Now we follow her **web traffic**.

### Query:

```spl
index="botsv2" sourcetype="stream:http" "10.0.2.101"
```

This shows **everything** she visited (too much noise).

---

### 🔥 Narrow it down smartly

We know:

- Company = beer industry
    
- Competitor = also beer
    

### Refined Query:

```spl
index="botsv2" sourcetype="stream:http" "10.0.2.101" *beer*
| dedup site
| table site
```

### 🧠 Why this works:

- `*beer*` → filters relevant industry
    
- `dedup` → removes repeated visits
    
- `table` → clean output
    

### ✅ Answer:

- **[www.berkbeer.com](http://www.berkbeer.com)**
    

---

## 🖼️ Step 3: Find CEO Contact Image

Now we zoom into that site.

### Query:

```spl
index="botsv2" sourcetype="stream:http" "10.0.2.101" "www.berkbeer.com"
```

### 🧠 Logic:

- HTTP logs show **URI paths**
    
- Images often contain contact info
    

### ✅ Answer:

- `/images/ceoberk.png`
    

---

## 📧 Step 4: Email Communication

Now we pivot from:  
👉 Web → Email

### Query:

```spl
index="botsv2" sourcetype="stream:smtp" "berkbeer.com"
```

### 🧠 Why SMTP?

- Emails travel via SMTP
    
- Often stored in **plaintext logs**
    

---

### What do we extract?

From raw email:

- CEO name → **Martin Berk**
    
- Email → **[mberk@berkbeer.com](mailto:mberk@berkbeer.com)**
    

---

## 📎 Step 5: Follow the Email Trail

We look deeper into the same SMTP logs.

### Findings:

- Amber → [hbernhard@berkbeer.com](mailto:hbernhard@berkbeer.com)
    
- Attachment → **Saccharomyces_cerevisiae_patent.docx**
    

### 🧠 Insight:

This is **intellectual property leakage**.

---

## 💀 Step 6: Hidden Email (Base64)

You notice encoded text.

👉 Decode it (CyberChef style)

### Result:

- **[ambersthebest@yeastiebeastie.com](mailto:ambersthebest@yeastiebeastie.com)**
    

### 🧠 Insight:

- Personal email = exfil channel
    
- Classic insider move
    

---

# 🧅 200 SERIES — ATTACK PHASE

Now things escalate from insider → external attacker.

---

## 🧠 Step 1: Tor Installation

### Query:

```spl
index="botsv2" amber tor install
| sort -_time desc
```

### 🧠 Why?

- Tor = anonymity
    
- Suspicious for corporate user
    

### ✅ Answer:

- **7.0.4**
    

---

## 🌐 Step 2: brewertalk.com IP

### Query:

```spl
index="botsv2" source="stream:dns" "www.brewertalk.com"
```

### 🧠 Logic:

- DNS logs = domain → IP mapping
    

### ✅ Answer:

- **52.42.208.228**
    

---

## 🚨 Step 3: Find Attacker

### Query:

```spl
index="botsv2" source="stream:http" "www.brewertalk.com"
| stats count by src_ip
```

### 🧠 Logic:

- Scanner = sends MANY requests
    

### ✅ Answer:

- **45.77.65.211**
    

---

## 🎯 Step 4: Targeted Endpoint

### Query:

```spl
index="botsv2" src_ip="45.77.65.211"
| stats count by uri_path
```

### 🧠 Logic:

- Attackers repeat same endpoint
    

### ✅ Answer:

- **/member.php**
    

---

## 💉 Step 5: SQL Injection

### Query:

```spl
index="botsv2" src_ip="45.77.65.211" uri_path="/member.php" select
```

### 🧠 Insight:

- SQL keywords = injection attempt
    

### ✅ Answer:

- **updatexml**
    

---

## 🍪 Step 6: XSS Attack

### Query:

```spl
index="botsv2" sourcetype="stream:http" kevin "<script>"
```

### 🧠 Why `<script>`?

- Classic XSS payload
    

### ✅ Answer:

- **1502408189**
    

---

## 🎭 Step 7: Fake Account

### 🧠 Insight:

- XSS used to steal token
    
- Then create account
    

### ✅ Answer:

- **kIagerfield**
    

---

# 💻 300 SERIES — RANSOMWARE

---

## 📊 Step 1: Encrypted File

### Query:

```spl
index="botsv2" host="MACLORY-AIR13" *.ppt*
```

### 🧠 Logic:

- Compare before vs after encryption
    

### ✅ Answer:

- **Frothly_marketing_campaign_Q317.pptx.crypt_**
    

---

## 🎬 Step 2: Movie File

### Query:

```spl
index="botsv2" *crypt* (game OR thrones)
```

### ✅ Answer:

- **S07E02**
    

---

## 🔌 Step 3: USB Infection

### Query:

```spl
index="botsv2" kutekitten usb
```

### 🧠 Logic:

- USB = common malware delivery
    

### ✅ Answer:

- **Alcor Micro Corp.**
    

---

## 🧬 Step 4: Malware Language

### Method:

- Extract hash → check VirusTotal
    

### ✅ Answer:

- **Perl**
    

---

## 🌐 Step 5: C2 Communication

### Findings:

- **eidk.duckdns.org**
    
- **eidk.hopto.org**
    

---

# 📦 400 SERIES — APT ATTACK

---

## 📎 Step 1: Phishing Attachment

### Query:

```spl
index="botsv2" sourcetype="stream:smtp" .zip
```

### ✅ Answer:

- **invoice.zip**
    

---

## 🔑 Step 2: Password

### 🧠 Found in email body

### ✅ Answer:

- **912345678**
    

---

## 🔐 Step 3: SSL Issuer

### Query:

```spl
index="botsv2" dest_ip="45.77.65.211" SSL
```

### ✅ Answer:

- **C = US**
    

---

## 📥 Step 4: Suspicious File

### 🧠 Clue:

- Non-English file → anomaly
    

### ✅ Answer:

- Korean `.hwp` file
    

---

## 🧑 Step 5: Victim

### ✅ Answer:

- **Ryan Kovar**
    

---

## 🧩 Step 6: Hidden Keyword

### ✅ Answer:

- **CyberEastEgg**
    

---

## ⏱️ Step 7: Persistence

### Query:

```spl
index="botsv2" schtasks.exe sourcetype=wineventlog create
```

### 🧠 Decode registry → base64

### ✅ Answer:

- **process.php**
    

---

# ⚡ FINAL ANALYST TAKE

This entire lab is basically a story:

- Insider (Amber) → leaks data
    
- Uses Tor → hides tracks
    
- External attacker → exploits web app
    
- Malware → spreads via USB
    
- APT → persists via scheduled tasks
    

---
