# Module 01 — Password-Based Attacks (Password Spraying & Throttling Brute Force)

**MITRE ATT&CK Mapping:** `T1110.003` (Password Spraying), `T1110.001` (Password Guessing), `T1078.004` (Valid Accounts: Cloud Accounts)  
**Telemetry Source:** Microsoft Entra ID Sign-In Logs (`sourcetype="azure:aad:signin"`)  
**Validation Status:** Validated with 4 Splunk Screenshots (`index="task-2"`)

---

## 1. Base Telemetry Filter

To isolate actionable failed authentication attempts, events are filtered to exclude successful sign-ins (`status.errorCode=0`) and events where Conditional Access succeeded despite intermediate authentication steps:

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, status.errorCode, status.failureReason
| sort - _time
```

* **Observed Telemetry (`22` failed events):** All failures occurred against `OfficeHome` with `status.errorCode=50126` (*"Error validating credentials due to invalid username or password"*).
* **Evidence:** [`../../evidence/screenshots/01-password-attacks-failed-signins-timeline.png`](../../evidence/screenshots/01-password-attacks-failed-signins-timeline.png)

---

## 2. Detection A — Password Spraying (One IP → Many Accounts)

Password spraying distributes a small number of password guesses across many accounts to evade account lockout thresholds. Grouping failed sign-ins by `ipAddress` and counting distinct `userPrincipalName` values surfaces horizontal spray activity.

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress
| sort - failures
```

### Observed Findings
* **Attacker IP:** `94.20.222.248` (Country: `AZ`)
* **Scope:** Targeted **7 unique accounts** (`rafael.maciel`, `igor.bicalho`, `guilherme.vidigal`, `miguel.lara`, `andre.oliveira`, `allan.smith`, `cristian.roberto`) with **14 failed attempts** (`50126`) between `2026-02-25 12:33:17` and `12:34:46`.
* **Evidence:** [`../../evidence/screenshots/01-password-spray-ip-aggregation.png`](../../evidence/screenshots/01-password-spray-ip-aggregation.png)

---

## 3. Detection B — Throttling Brute Force (One IP → Single Account)

Throttling brute-force attacks focus repeatedly on a single account using paced intervals (several minutes apart) to blend into normal traffic. Grouping by both `ipAddress` and `userPrincipalName` isolates targeted vertical attacks.

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| stats count as failures, dc(userPrincipalName) as targeted_accounts by ipAddress, userPrincipalName
| sort - failures
```

### Observed Findings
* **Attacker IP:** `38.165.231.218` (Country: `MX`)
* **Targeted Account:** `amanda.costa@finegalo.thm` (`targeted_accounts = 1`)
* **Paced Cadence:** 4 failed attempts (`50126`) spaced ~7 minutes apart (`12:39:15`, `12:46:35`, `12:53:26`, `13:00:18`), distinct from the 2-failures-per-account pattern of `94.20.222.248`.
* **Evidence:** [`../../evidence/screenshots/01-throttling-bruteforce-per-user-ip.png`](../../evidence/screenshots/01-throttling-bruteforce-per-user-ip.png)

---

## 4. Compromise Verification Pivot (Successful Sign-In Check)

Following detection of the throttling brute force against `amanda.costa@finegalo.thm`, pivoting to `status.errorCode=0` confirms whether the attacker obtained valid credentials.

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0
| where userPrincipalName="amanda.costa@finegalo.thm"
| stats count by userPrincipalName, status.errorCode, ipAddress
| sort status.errorCode
```

### Observed Findings
* **Compromised Account:** `amanda.costa@finegalo.thm`
* **Confirmed Malicious Access:** **3 successful authentications** (`status.errorCode=0`) originated directly from the brute-force source IP `38.165.231.218`.
* **Evidence:** [`../../evidence/screenshots/01-throttling-bruteforce-compromise-pivot.png`](../../evidence/screenshots/01-throttling-bruteforce-compromise-pivot.png)

---

## False Positives & Tuning Guidance
* **False Positives:** Misconfigured service accounts, shared NAT gateways, or users with cached expired passwords on mobile mail clients.
* **Tuning:** Exclude known corporate egress NAT IPs and correlate failure bursts with subsequent `status.errorCode=0` events from the same `/24` subnet or ASN.
