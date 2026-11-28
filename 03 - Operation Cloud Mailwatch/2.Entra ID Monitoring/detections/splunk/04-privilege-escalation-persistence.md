# Module 04 — Privilege Escalation & Identity Persistence

**MITRE ATT&CK Mapping:** `T1136.003` (Create Account: Cloud Account), `T1098.003` (Additional Cloud Roles), `T1098.005` (Device Registration)  
**Telemetry Source:** `azure:aad:audit`  
**Validation Status:** Validated with 2 Splunk Screenshots (`index="task-5"`)

---

## 1. Rogue Cloud Account Creation (`Add user`)

Monitors Entra ID directory audit logs for newly provisioned user principals and extracts both the initiating actor and target user.

```spl
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add user"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval userCreated='targetResources{}.userPrincipalName'
| table _time, activityDisplayName, initiator, userCreated
```

### Observed Findings
* **Timestamp:** `2026-03-04 13:31:48.764` (5 minutes after the MFA fatigue compromise of `igor.bicalho@finegalo.thm`)
* **Initiating Actor:** `igor.bicalho@finegalo.thm`
* **Created Backdoor Account:** `rafael.maciel@finegalo.thm`
* **Evidence:** [`../../evidence/screenshots/04-rogue-user-creation-audit.png`](../../evidence/screenshots/04-rogue-user-creation-audit.png)

---

## 2. Privileged Directory Role Assignment (`Add member to role`)

Tracks directory role assignments to detect immediate privilege escalation of newly created or compromised accounts.

```spl
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add member to role"
| table _time, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue
| sort - _time
```

### Observed Findings
* **Timestamp:** `2026-03-04 13:31:49.154` (immediately following account creation)
* **Initiating Actor:** `igor.bicalho@finegalo.thm`
* **Target Account:** `rafael.maciel@finegalo.thm`
* **Assigned Privileged Role:** `Global Administrator` (Role Template ID `62e90394-69f5-4237-9190-012177145e10` / `TenantAdmins`)
* **Evidence:** [`../../evidence/screenshots/04-privileged-role-assignment-audit.png`](../../evidence/screenshots/04-privileged-role-assignment-audit.png)

---

## 3. Unauthorized MFA / Security Info Registration

Detects adversaries registering their own authentication device/method to maintain persistent access even if the compromised password is reset.

```spl
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="User started security info registration" loggedByService="Authentication Methods" operationType="Add"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| table _time, activityDisplayName, initiator, initiatedBy.user.ipAddress, additionalDetails{}.value
```

### Observed Findings
* **Persistence Timestamp:** `2026-03-04 13:36` (attacker added a new MFA device/security info method).

---

## False Positives & Tuning Guidance
* **False Positives:** Authorized IT onboarding workflows, Privileged Identity Management (PIM) just-in-time activations, and legitimate user device enrollment.
* **Tuning:** Correlate `Add user` + `Add member to role` (`Global Administrator`) + `User started security info registration` occurring within a 30-minute window outside approved change tickets.
