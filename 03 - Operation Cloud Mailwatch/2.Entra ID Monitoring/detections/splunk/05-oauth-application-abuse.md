# Module 05 — OAuth Application Abuse & High-Risk Consent Monitoring

**MITRE ATT&CK Mapping:** `T1528` (Steal Application Access Token), `T1098.001` (Additional Cloud Credentials)  
**Telemetry Source:** `azure:aad:audit`  
**Validation Status:** Detection Logic Documented (Reference Module)

---

## 1. OAuth Application Consent Hunt (`Consent to application`)

Adversaries abuse malicious OAuth applications to obtain persistent Graph API access without needing ongoing user passwords or MFA challenges. Tracking `activityDisplayName="Consent to application"` surfaces all user and admin consent grants.

```spl
index=* sourcetype="azure:aad:audit" activityDisplayName="Consent to application"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval targetApp='targetResources{}.displayName'
| eval grantedPermissions='targetResources{}.modifiedProperties{}.newValue'
| table _time, activityDisplayName, initiator, targetApp, grantedPermissions
| sort - _time
```

---

## 2. High-Impact Graph Permission Risk Focus (`Mail.Read.All`)

* **Critical Application Permission:** `Mail.Read.All`
* **Security Impact:** Grants an application-level permission to read all emails across **every mailbox in the tenant** without signed-in user interaction, enabling silent data exfiltration and business email compromise (BEC) reconnaissance.
* **Audit Indicator:** `activityDisplayName="Consent to application"` in `azure:aad:audit`.

---

## False Positives & Tuning Guidance
* **False Positives:** Approved enterprise SaaS integrations (e.g., third-party archiving, eDiscovery, or security platforms) consented by verified Global/Application Administrators.
* **Tuning:** Restrict user consent to unverified publishers in Entra ID and alert immediately whenever `Mail.Read.All`, `Mail.ReadWrite`, `Directory.ReadWrite.All`, or `RoleManagement.ReadWrite.Directory` appears in consent audit events.
