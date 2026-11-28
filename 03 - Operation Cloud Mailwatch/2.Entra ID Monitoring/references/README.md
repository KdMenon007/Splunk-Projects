# Technical References

Supporting log schemas, Entra ID error codes, and MITRE ATT&CK mappings referenced in **Operation Cloud Mailwatch**.

---

## 1. Splunk Sourcetypes Used

| Sourcetype | Log Category | Primary Fields Used |
| :--- | :--- | :--- |
| `azure:aad:signin` | Interactive & Non-Interactive Sign-Ins | `userPrincipalName`, `ipAddress`, `location.countryOrRegion`, `appDisplayName`, `status.errorCode`, `status.failureReason`, `conditionalAccessStatus`, `appliedConditionalAccessPolicies{}` |
| `azure:aad:identity_protection:risky_user` | Entra ID Identity Protection | `userPrincipalName`, `riskLevel`, `riskState`, `riskDetail` |
| `azure:aad:audit` | Entra ID Directory Audit Logs | `activityDisplayName`, `loggedByService`, `operationType`, `initiatedBy.user.userPrincipalName`, `targetResources{}.userPrincipalName`, `targetResources{}.modifiedProperties{}.newValue` |

---

## 2. Entra ID Sign-In Error Codes (`status.errorCode`)

| Error Code | Meaning | Investigative Significance |
| :--- | :--- | :--- |
| `0` | Success | Authentication succeeded; used to pivot from brute-force/MFA failures to confirmed compromise |
| `50126` | Invalid username or password | Primary indicator in password spraying and throttling brute-force attacks |
| `50074` | Strong authentication is required | User did not complete required MFA challenge |
| `50076` | Strong authentication required due to location/risk policy | MFA triggered by risk or Conditional Access change |
| `500121` | Authentication failed during strong authentication request | Primary indicator of MFA prompt denial / MFA fatigue (`prompt bombing`) |

---

## 3. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Project Module |
| :--- | :--- | :--- |
| `T1110.003` | Brute Force: Password Spraying | Module 01 |
| `T1110.001` | Brute Force: Password Guessing | Module 01 |
| `T1078.004` | Valid Accounts: Cloud Accounts | Modules 01, 02 |
| `T1621` | Multi-Factor Authentication Request Generation | Module 03 |
| `T1136.003` | Create Account: Cloud Account | Module 04 |
| `T1098.003` | Account Manipulation: Additional Cloud Roles | Module 04 |
| `T1098.005` | Account Manipulation: Device Registration | Module 04 |
| `T1528` | Steal Application Access Token | Module 05 |
