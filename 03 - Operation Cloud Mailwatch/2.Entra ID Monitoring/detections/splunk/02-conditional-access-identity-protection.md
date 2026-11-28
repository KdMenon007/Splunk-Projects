# Module 02 — Conditional Access & Identity Protection Monitoring

**MITRE ATT&CK Mapping:** `T1078.004` (Valid Accounts: Cloud Accounts), `T1090` (Proxy / Anonymized Infrastructure)  
**Telemetry Sources:** `azure:aad:identity_protection:risky_user`, `azure:aad:signin`  
**Validation Status:** Validated with 2 Splunk Screenshots (`index="task-3"`)

---

## 1. Identity Protection Risky User Hunt

Queries Microsoft Entra ID Identity Protection telemetry to surface accounts flagged for elevated sign-in or user risk.

```spl
index="task-3" sourcetype="azure:aad:identity_protection:risky_user"
| table _time, userPrincipalName, riskLevel, riskState, riskDetail
| sort - _time
```

### Observed Findings
* **Flagged Risky User:** `allan.senna@finegalo.thm`
* **Risk State & Level:** `riskLevel=high`, `riskState=atRisk` (event recorded at `2026-03-03 19:46:39`; last risky sign-in context `2026-03-03 13:51` / `anonymizedIPAddress`).
* **Evidence:** [`../../evidence/screenshots/02-risky-user-identity-protection.png`](../../evidence/screenshots/02-risky-user-identity-protection.png)

---

## 2. Conditional Access Policy (CAP) Enforcement & Block Analysis

Parses nested `appliedConditionalAccessPolicies{}` JSON arrays within Entra ID sign-in logs to identify which specific Conditional Access policy blocked an authentication attempt.

```spl
index="task-3" sourcetype="azure:aad:signin" conditionalAccessStatus=failure
| spath output=policies path=appliedConditionalAccessPolicies{}
| mvexpand policies
| spath input=policies output=policy_result path=result
| spath input=policies output=policy_name path=displayName
| where policy_result="failure"
| stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus
| eval FailedPolicies=mvjoin(FailedPolicies, ", ")
| table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies
| sort - _time
```

### Observed Findings (`6` blocked events)
* **Enforced Blocking Policy:** `Block Suspicious Countries`
* **Target User & App:** `Allan Senna` (`allan.senna@finegalo.thm`) accessing `OfficeHome`
* **Blocked Source IPs:**
  * `94.20.222.251` — **5 blocked attempts** (`13:30:26`, `13:30:44`, `13:30:54`, `13:31:04`, `13:31:16`)
  * `94.20.222.248` — **1 blocked attempt** (`12:51:53`, same source IP observed in Module 01 password spraying)
* **Evidence:** [`../../evidence/screenshots/02-conditional-access-block-suspicious-countries.png`](../../evidence/screenshots/02-conditional-access-block-suspicious-countries.png)

---

## False Positives & Tuning Guidance
* **False Positives:** Traveling employees using commercial VPNs or corporate split-tunnel proxies.
* **Tuning:** Cross-reference `anonymizedIPAddress` alerts with approved corporate VPN egress ranges and verify whether Conditional Access enforcement (`conditionalAccessStatus=failure`) successfully blocked token issuance.
