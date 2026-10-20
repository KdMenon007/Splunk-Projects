# Data Dictionary — Phase 1

| Field | Source | Use |
|---|---|---|
| `_time` | All | Splunk event timestamp; validate timezone |
| `userPrincipalName` | Entra sign-in | Account associated with sign-in |
| `ipAddress` | Entra sign-in | Source IP pivot |
| `appDisplayName` | Entra sign-in | Application context |
| `status.errorCode` | Entra sign-in | Authentication result code |
| `clientAppUsed` | Entra sign-in | Client context |
| `conditionalAccessStatus` | Entra sign-in | Policy result |
| `activityDisplayName` | Entra audit | Recorded action |
| `initiatedBy.user.userPrincipalName` | Entra audit | User actor, if present |
| `initiatedBy.app.displayName` | Entra audit | App actor, if present |
| `targetResources{}.userPrincipalName` | Entra audit | Target user |
| `targetResources{}.modifiedProperties` | Entra audit | Changed properties, if present |
| `result` | Entra audit | Recorded outcome |
| `Operation` | M365 activity | Workload operation |
| `UserId` | M365 activity | Associated account |
| `ClientIP` / `ClientIPAddress` | M365 activity | Source/client IP |
| `Workload` | M365 activity | Workload name |
| `ObjectId` | M365 activity | Object identifier/details |

Schemas vary by connector and version. Inspect representative raw events before treating this dictionary as authoritative in another environment.
