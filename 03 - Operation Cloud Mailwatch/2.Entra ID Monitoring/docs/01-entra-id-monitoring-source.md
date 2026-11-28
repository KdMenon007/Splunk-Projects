# 01 — Entra ID Monitoring (Preserved Source Notes)

> **Preservation Notice:** This file preserves the exact investigation notes provided for Tasks 2 through 6 without altering the original wording or analytical sequence.

---

Task 2: Password-Based Attack
This task involves analyzing Entra ID sign-in logs to detect patterns associated with password-based attacks.

Base Filter Explanation
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
Explanation
- index="task-2" limits the search to the dataset relevant to Task 2.
- sourcetype="azure:aad:signin" ensures that only Azure AD sign-in logs are analyzed.
- "status.errorCode"!=0 filters for failed authentication attempts. In Entra ID logs, an error code of 0 indicates a successful login.
- conditionalAccessStatus!=success removes events where Conditional Access evaluation succeeded, even if intermediate steps had errors.
This filter ensures that the dataset contains only relevant failed login attempts, which is essential when identifying brute-force or spraying attacks.

Question 1: Which IP address is performing a password spraying?
Query Used
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress
| sort - failures
Explanation
- stats aggregates the data.
- dc(userPrincipalName) counts the number of unique users targeted by each IP address.
- count as failures counts the total number of failed login attempts.
- by ipAddress groups the results per IP address.
- sort - failures sorts the results in descending order to highlight the most active IP.

Analysis
Password spraying is characterized by one IP attempting to authenticate against multiple user accounts using a limited set of passwords. Therefore, the IP with the highest number of targeted accounts is of particular interest.
From the results, one IP address stands out by targeting multiple accounts with several failed attempts.
Answer: 94.20.222.248

Question 2: Which IP address is performing a throttling brute force?
Query Used
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| stats count as failures, dc(userPrincipalName) as targeted_accounts by ipAddress, userPrincipalName
| sort - failures
Explanation
- stats count as failures counts failed attempts.
- dc(userPrincipalName) still tracks how many distinct users are targeted.
- Including userPrincipalName in the grouping allows us to analyze behavior per user per IP.

Analysis
Throttling brute-force attacks differ from password spraying in that they:
- Target a single user account
- Perform repeated login attempts over time to avoid detection or lockouts
The goal is to identify an IP address that:
- Targets only one user (targeted_accounts = 1)
- Has multiple failed attempts against that user
From the results, one IP clearly shows repeated failures against a single account.
Answer: 38.165.231.218

Question 3: What is the user’s email address that was compromised?

Analysis
From the throttling brute-force query results:
- The IP address 38.165.231.218 is associated with repeated failed attempts
- It targets only one user account
This strongly indicates that the attacker focused on a specific user. In real-world investigations, this would be followed by checking for successful authentication attempts from the same IP.
The user associated with this activity is identified directly in the query results.
Answer: amanda.costa@finegalo.thm

---

Task 3: Conditional Access Policy and Identity Protection
This task focuses on identifying risky users and understanding how Conditional Access Policies respond to suspicious activity.

Base Filter for Risky Users
index="task-3" sourcetype="azure:aad:identity_protection:risky_user"
| table _time, userPrincipalName, riskLevel, riskState, riskDetail
| sort - _time
Explanation
- index="task-3" specifies the dataset for this task.
- sourcetype="azure:aad:identity_protection:risky_user" retrieves logs related to risky users detected by Entra ID Identity Protection.
- table selects relevant fields for analysis.
- sort - _time ensures the most recent events are displayed first.

Question 1: What is the user email address that is at risk in the tenant?

Analysis
The query lists users flagged by Identity Protection as risky. The most recent entry indicates the user currently considered at risk within the tenant.
Answer: allan.senna@finegalo.thm

Question 2: When was the last risky sign-in attempt from this risky user?
Analysis
The _time field represents when the event occurred. Since the results are sorted in descending order, the first entry corresponds to the most recent risky sign-in attempt.
Answer: 2026–03–03 13:51

Question 3: What is the type of risk identified during this risky user sign-in?
Analysis
The riskDetail field provides context about why the sign-in was flagged. In this case, the detection indicates that the login originated from an anonymized IP address, which is commonly associated with VPNs or proxy services.
Answer: anonymizedIPAddress

Conditional Access Policy Investigation
Query Used
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

Explanation
- conditionalAccessStatus=failure filters for sign-in attempts blocked by Conditional Access.
- spath extracts nested JSON fields from the logs.
- mvexpand separates multiple policy entries into individual records.
- Additional spath commands extract the policy name and result.
- where policy_result="failure" ensures only failed policy evaluations are considered.
- stats values(policy_name) aggregates all failed policies for each event.
- mvjoin formats multiple policy names into a readable string.
- table organizes the output for clarity.

Question 4: What is the name of the CAP policy that was enforced and blocked some sign-in attempts?

Analysis
The query reveals which Conditional Access Policies were applied and resulted in blocking access. The relevant policy is identified in the FailedPolicies field.
Answer: Block Suspicious Countries

Question 5: What was the IP address that was blocked from signing in this risky user?

Analysis
From the same query results, the ipAddress field shows the source of the blocked authentication attempt associated with the enforced policy.
Answer: 94.20.222.251

---

Task 4: MFA Bypass Techniques
In this task, the focus shifts to identifying techniques used to bypass Multi-Factor Authentication (MFA), specifically MFA fatigue (prompt bombing). Unlike password-based attacks, these techniques rely heavily on user behavior rather than breaking authentication mechanisms.

Base Query for MFA Failures
index="task-4" sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)
| stats count as mfa_failures values(status.errorCode) as errorCodes values(status.failureReason) as failureReasons by userPrincipalName, ipAddress
| sort - mfa_failures
Explanation
- index="task-4" specifies the dataset for this task.
- sourcetype="azure:aad:signin" filters for Entra ID sign-in logs.
- (status.errorCode=50074 OR 50076 OR 500121) filters for MFA-related failures:
- These error codes indicate failed MFA challenges such as denied prompts or incomplete authentication.
- stats count as mfa_failures counts how many MFA failures occurred.
- values(status.errorCode) lists all MFA-related error codes observed.
- values(status.failureReason) provides context for the failures.
- by userPrincipalName, ipAddress groups results per user and source IP.
- sort - mfa_failures highlights the most targeted user.
This query helps identify accounts experiencing a high volume of MFA prompts, which is a key indicator of MFA fatigue attacks.

Question 1: Which user was the target of an MFA fatigue attack?

Analysis
The query output highlights the user with the highest number of MFA failures. MFA fatigue attacks are characterized by repeated authentication prompts sent to a single user in a short period.
The user with the highest count of MFA failures is the most likely target.
Answer: igor.bicalho@finegalo.thm

Question 2: What is the error code of the failed MFA prompts?

Analysis
From the query results, the error codes associated with the repeated MFA failures are examined. Among the listed codes, one appears consistently in the attack pattern.
Error code 500121 is commonly associated with MFA denial or failure scenarios, which aligns with a user repeatedly rejecting or ignoring authentication prompts.
Answer: 500121

Question 3: What is the country code that the user normally signs in before the attack?
Query Used
index="task-4" sourcetype="azure:aad:signin" status.errorCode=0
| table _time, userPrincipalName, ipAddress, location.countryOrRegion
| sort - _time
Explanation
- status.errorCode=0 filters for successful logins only.
- The table command displays relevant fields such as timestamp, user, IP address, and country.
- Sorting by time allows us to observe login patterns over time.
Analysis

To determine normal behavior, we examine historical successful logins for the identified user. The logs show repeated sign-ins from the same country over multiple timestamps, establishing a clear baseline.
A sudden deviation from this pattern typically indicates suspicious activity.
From the dataset:
- Multiple successful logins originate from DK
- A later login appears from a different country, indicating a deviation
Thus, the repeated country represents the user’s normal sign-in location.
Answer: DK

Question 4: When does the attacker successfully authenticate in the user account?
Query Used
index="task-4" sourcetype="azure:aad:signin"
| search userPrincipalName="igor.bicalho@finegalo.thm"
| table _time, status.errorCode, ipAddress, location.countryOrRegion
| sort _time
Explanation
- The query filters all sign-in activity for the targeted user.
- Including status.errorCode allows differentiation between failed and successful attempts.
- sort _time arranges events chronologically to reconstruct the attack sequence.
Analysis

The attack pattern follows a clear sequence:
1. Multiple MFA failures (error codes such as 500121)
2. Followed by a successful authentication (status.errorCode=0)
3. From a new IP address and different geographic location
By examining the timeline, the first successful login after repeated MFA failures marks the moment the attacker gained access.
The logs show:
- Normal activity from Denmark (DK)
- A sudden successful login from Brazil (BR)
This deviation confirms the compromise event.
Answer: 2026–03–04 13:26

---

Task 5: Privilege Escalation and Persistence
This task focuses on identifying how an attacker, after gaining access, escalates privileges and establishes persistence within the tenant. The analysis is based on audit logs, which track administrative and configuration changes in Entra ID.

Question 1: What is the user email address that the attacker created?
Query Used
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add user"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval userCreated='targetResources{}.userPrincipalName'
| table _time, activityDisplayName, initiator, userCreated
Explanation
- sourcetype="azure:aad:audit" retrieves audit logs, which record administrative actions.
- activityDisplayName="Add user" filters for events where a new user account was created.
- eval initiator=coalesce(...) identifies who performed the action:
- If a user initiated it, their username is shown
- Otherwise, the application name is used
- eval userCreated='targetResources{}.userPrincipalName' extracts the newly created user account from nested log fields.
- table formats the output for clarity.

Analysis
This query reveals newly created accounts along with the actor responsible for the action. In a post-compromise scenario, attackers often create new accounts to maintain access even if the original account is detected or disabled.
The results show a newly created user account associated with suspicious activity.
Answer: rafael.maciel@finegalo.thm

Question 2: Which role was assigned to this new account?
Query Used
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add member to role"
| table _time, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue
| sort - _time
Explanation
- activityDisplayName="Add member to role" filters for role assignment events.
- The query captures:
- Who performed the action (initiatedBy.user.userPrincipalName)
- Which user received the role (targetResources{}.userPrincipalName)
- Role details stored in modifiedProperties

Analysis
After creating a new account, attackers typically assign elevated privileges to it. This allows them to:
- Maintain control over the environment
- Perform administrative actions
- Avoid relying on the initially compromised account
The logs show that the newly created account was assigned a highly privileged role.
Answer: Global Administrator

Question 3: When did the attacker add a new MFA device?
Query Used
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="User started security info registration" loggedByService="Authentication Methods" operationType="Add"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| table _time, activityDisplayName, initiator, initiatedBy.user.ipAddress, additionalDetails{}.value
Explanation
- activityDisplayName="User started security info registration" identifies MFA registration events.
- loggedByService="Authentication Methods" ensures the event is related to authentication configuration.
- operationType="Add" filters for newly added authentication methods.
- eval initiator=coalesce(...) identifies who initiated the action.
- additionalDetails{}.value may contain information about the MFA method added.

Analysis
Adding a new MFA device is a common persistence technique. Once an attacker registers their own authentication method:
- They can continue accessing the account even if the password is reset
- They effectively establish long-term control over the identity
The timestamp associated with this action indicates when persistence was established.
Answer: 2026–03–04 13:36

---

Task 6: OAuth Application Abuse
This task focuses on detecting and understanding abuse of OAuth applications within Entra ID. Attackers can exploit granted application permissions to access sensitive data without directly compromising user credentials.

Question 1: Which permission allows an application to read all mailboxes within a tenant?
Explanation
- OAuth applications can request delegated or application permissions to access Microsoft 365 resources.
- Mail.Read.All is an application-level permission that grants the app access to read all emails in all mailboxes across the tenant.
- This permission is high-risk because once granted, the application can access mailbox data without further authentication, making it a common target for attackers seeking lateral movement or data exfiltration.
Answer: Mail.Read.All

Question 2: What is the activityDisplayName value used to track all consent grants to applications within Entra ID audit logs?
Explanation
- Entra ID audit logs track administrative and user activity, including consent events.
- The specific activityDisplayName value "Consent to application" corresponds to events where a user or admin grants permissions to an application.
- Monitoring these events is crucial because excessive or suspicious consent grants may indicate abuse by malicious applications, potentially bypassing MFA or other controls.
Answer: Consent to applicatio
