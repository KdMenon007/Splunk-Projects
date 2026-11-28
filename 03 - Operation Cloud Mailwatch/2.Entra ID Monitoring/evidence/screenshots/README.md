# Evidence & Validation Screenshots

This directory stores **11 verified Splunk screenshots** captured during investigation and detection validation across Modules 01–04.

---

## Complete Screenshot Inventory

| File Name | Module | Splunk Query / View Captured | Key Evidence Shown |
| :--- | :--- | :--- | :--- |
| [`01-password-attacks-failed-signins-timeline.png`](01-password-attacks-failed-signins-timeline.png) | Module 01 | Base failed sign-in filter (`index="task-2"`, `22 events`) | Chronological `50126` failures across `94.20.222.248` (`AZ`), `149.102.234.27` (`BR`), and `38.165.231.218` (`MX`) |
| [`01-password-spray-ip-aggregation.png`](01-password-spray-ip-aggregation.png) | Module 01 | `stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress` | `94.20.222.248` targeting `7` accounts (`14` failures) and `38.165.231.218` targeting `1` account (`4` failures) |
| [`01-throttling-bruteforce-per-user-ip.png`](01-throttling-bruteforce-per-user-ip.png) | Module 01 | `stats count as failures, dc(userPrincipalName) as targeted_accounts by ipAddress, userPrincipalName` | `38.165.231.218` targeting `amanda.costa@finegalo.thm` (`4` failures, `targeted_accounts=1`) vs. `94.20.222.248` (`2` failures across each of 7 users) |
| [`01-throttling-bruteforce-compromise-pivot.png`](01-throttling-bruteforce-compromise-pivot.png) | Module 01 | `status.errorCode=0` pivot for `amanda.costa@finegalo.thm` | `3` successful logins (`status.errorCode=0`) from `38.165.231.218` confirming account compromise |
| [`02-risky-user-identity-protection.png`](02-risky-user-identity-protection.png) | Module 02 | `sourcetype="azure:aad:identity_protection:risky_user"` (`index="task-3"`) | `allan.senna@finegalo.thm` flagged with `riskLevel=high`, `riskState=atRisk` at `2026-03-03 19:46:39` |
| [`02-conditional-access-block-suspicious-countries.png`](02-conditional-access-block-suspicious-countries.png) | Module 02 | `conditionalAccessStatus=failure` with `spath` policy extraction (`index="task-3"`, `6 events`) | `Block Suspicious Countries` blocked `Allan Senna` on `OfficeHome` from `94.20.222.251` (`5` times) and `94.20.222.248` (`1` time) |
| [`03-mfa-fatigue-500121-summary.png`](03-mfa-fatigue-500121-summary.png) | Module 03 | `status.errorCode=50074 OR 50076 OR 500121` stats (`index="task-4"`, `10 events`) | `igor.bicalho@finegalo.thm` targeted from `149.102.234.27` with `10` `mfa_failures` (`500121`) |
| [`03-mfa-baseline-country-signins.png`](03-mfa-baseline-country-signins.png) | Module 03 | `status.errorCode=0` successful sign-ins (`index="task-4"`, `7 events`) | `6` baseline logins from `96.0.24.134` (`DK`) followed by `1` anomalous login from `149.102.234.27` (`BR`) at `2026-03-04 13:26:22` |
| [`03-mfa-fatigue-dk-to-br-timeline.png`](03-mfa-fatigue-dk-to-br-timeline.png) | Module 03 | Chronological sign-in reconstruction for `igor.bicalho@finegalo.thm` (`17 events`) | Full timeline showing `6` normal `DK` logins (`0`), `10` `BR` MFA denials (`500121`), and final `BR` compromise (`0`) at `13:26:22` |
| [`04-rogue-user-creation-audit.png`](04-rogue-user-creation-audit.png) | Module 04 | `activityDisplayName="Add user"` (`index="task-5"`, `1 event`) | `igor.bicalho@finegalo.thm` created `rafael.maciel@finegalo.thm` at `2026-03-04 13:31:48.764` |
| [`04-privileged-role-assignment-audit.png`](04-privileged-role-assignment-audit.png) | Module 04 | `activityDisplayName="Add member to role"` (`index="task-5"`, `1 event`) | `igor.bicalho@finegalo.thm` assigned `Global Administrator` (`TenantAdmins`) to `rafael.maciel@finegalo.thm` at `2026-03-04 13:31:49.154` |
