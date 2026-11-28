# SOC Investigation Playbooks

Standardized Tier-1 / Tier-2 SOC investigation, scoping, and containment procedures mapped to the five Entra ID threat modules in **Operation Cloud Mailwatch**.

---

## Playbook 01 — Password Spraying & Throttling Brute Force

1. **Triage & Scope:** Run the Module 01 IP aggregation query (`dc(userPrincipalName)` vs. `count(failures)`). Distinguish horizontal spraying (`94.20.222.248` targeting 7 users with 14 failures) from vertical throttling brute force (`38.165.231.218` targeting `amanda.costa@finegalo.thm` with 4 paced failures).
2. **Compromise Pivot:** Query `status.errorCode=0` for every targeted `userPrincipalName` and source `ipAddress` (confirmed 3 successful logins for `amanda.costa@finegalo.thm` from `38.165.231.218`).
3. **Containment:** Revoke active refresh tokens and force password reset for any compromised account; block offending source IPs/ASNs in Conditional Access Named Locations.

---

## Playbook 02 — Conditional Access & Identity Protection Risk

1. **Triage & Scope:** Inspect `azure:aad:identity_protection:risky_user` for `riskLevel`, `riskState`, and `riskDetail` (e.g., `allan.senna@finegalo.thm` flagged `riskLevel=high` / `riskState=atRisk` with `anonymizedIPAddress` risk context).
2. **Policy Verification:** Expand `appliedConditionalAccessPolicies{}` in `azure:aad:signin` to verify whether policies such as `Block Suspicious Countries` blocked the connection (`94.20.222.251` and `94.20.222.248`) or ran in report-only mode.
3. **Containment:** If any session bypassed Conditional Access, revoke sessions and require MFA re-registration.

---

## Playbook 03 — MFA Fatigue (Prompt Bombing) & Geographic Deviation

1. **Triage & Scope:** Identify accounts with spikes in error codes `500121`, `50074`, or `50076` (e.g., `igor.bicalho@finegalo.thm` hit with 10 `500121` failures from `149.102.234.27`).
2. **Baseline Comparison:** Compare the source country/ASN of any subsequent `status.errorCode=0` login against the user's successful sign-in baseline (e.g., baseline `96.0.24.134` in `DK` vs. compromise login from `149.102.234.27` in `BR` at `2026-03-04 13:26:22`).
3. **Containment:** Immediately revoke sessions, reset credentials, and audit all directory changes performed after the anomalous sign-in timestamp.

---

## Playbook 04 — Privileged Role Escalation & MFA Persistence

1. **Triage & Scope:** Query `azure:aad:audit` around the compromise window for `Add user`, `Add member to role`, and `User started security info registration`.
2. **Eradication:**
   - Delete or disable unauthorized accounts (`rafael.maciel@finegalo.thm`, created at `2026-03-04 13:31:48.764` by `igor.bicalho@finegalo.thm`).
   - Remove unauthorized `Global Administrator` (`TenantAdmins`) role assignments (`2026-03-04 13:31:49.154`).
   - Remove rogue authentication methods added during persistence (`2026-03-04 13:36`).
3. **Post-Incident Audit:** Review all actions initiated by both the initially compromised user (`igor.bicalho@finegalo.thm`) and the rogue administrator account (`rafael.maciel@finegalo.thm`).

---

## Playbook 05 — Malicious OAuth Application Consent

1. **Triage & Scope:** Filter `azure:aad:audit` for `activityDisplayName="Consent to application"` and inspect granted scopes.
2. **Risk Assessment:** Prioritize any grant requesting application permissions such as `Mail.Read.All`, `Files.Read.All`, or `Directory.ReadWrite.All`.
3. **Containment:** Disable the Enterprise Application / Service Principal in Entra ID, revoke OAuth2 permission grants, and audit mailbox access logs (`MailItemsAccessed`).
