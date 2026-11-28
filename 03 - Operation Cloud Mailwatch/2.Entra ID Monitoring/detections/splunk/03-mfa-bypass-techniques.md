# Module 03 — MFA Bypass Techniques (MFA Fatigue & Geographic Deviation)

**MITRE ATT&CK Mapping:** `T1621` (Multi-Factor Authentication Request Generation), `T1111` (Multi-Factor Authentication Interception)  
**Telemetry Source:** `azure:aad:signin`  
**Validation Status:** Validated with 3 Splunk Screenshots (`index="task-4"`)

---

## 1. MFA Fatigue / Prompt Bombing Detection

Detects high volumes of MFA challenge failures (`50074`, `50076`, `500121`) per user and source IP, indicating an adversary repeatedly triggering push notifications until the user approves one out of fatigue.

```spl
index="task-4" sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)
| stats count as mfa_failures values(status.errorCode) as errorCodes values(status.failureReason) as failureReasons by userPrincipalName, ipAddress
| sort - mfa_failures
```

### Observed Findings
* **Targeted User:** `igor.bicalho@finegalo.thm`
* **Attacker Source IP:** `149.102.234.27`
* **MFA Failure Volume:** **10 failed MFA prompts** (`status.errorCode=500121` — *"Authentication failed during strong authentication request."*)
* **Evidence:** [`../../evidence/screenshots/03-mfa-fatigue-500121-summary.png`](../../evidence/screenshots/03-mfa-fatigue-500121-summary.png)

---

## 2. Geographic Baseline & Compromise Timeline Reconstruction

Establishes the user's normal sign-in country using historical successful logins (`status.errorCode=0`), then reconstructs the full chronological sequence (`17 events`) of MFA failures and successful logins for `igor.bicalho@finegalo.thm`.

```spl
index="task-4" sourcetype="azure:aad:signin" status.errorCode=0
| table _time, userPrincipalName, ipAddress, location.countryOrRegion
| sort - _time
```

```spl
index="task-4" sourcetype="azure:aad:signin"
| search userPrincipalName="igor.bicalho@finegalo.thm"
| table _time, status.errorCode, ipAddress, location.countryOrRegion
| sort _time
```

### Observed Findings
* **Established User Baseline:** **6 normal successful logins** (`status.errorCode=0`) from IP `96.0.24.134` in **Denmark (`DK`)** between `2026-03-02 10:12:58` and `2026-03-04 12:20:22`.
* **Prompt Bombing Window:** **10 consecutive `500121` failures** from IP `149.102.234.27` in **Brazil (`BR`)** every ~6 minutes from `2026-03-04 12:30:06` to `13:24:13`.
* **Compromise Event Timestamp:** `2026-03-04 13:26:22` — first successful authentication (`status.errorCode=0`) from `149.102.234.27` (**Brazil (`BR`)**).
* **Evidence:**
  * [`../../evidence/screenshots/03-mfa-baseline-country-signins.png`](../../evidence/screenshots/03-mfa-baseline-country-signins.png)
  * [`../../evidence/screenshots/03-mfa-fatigue-dk-to-br-timeline.png`](../../evidence/screenshots/03-mfa-fatigue-dk-to-br-timeline.png)

---

## False Positives & Tuning Guidance
* **False Positives:** Users with poor cellular connectivity repeatedly retrying an MFA prompt, or legitimate international travel.
* **Tuning:** Alert with High severity when `>= 5` error `500121` events occur within 15 minutes and are immediately followed by `status.errorCode=0` from a new ASN or country (`location.countryOrRegion` != user's 30-day baseline).
