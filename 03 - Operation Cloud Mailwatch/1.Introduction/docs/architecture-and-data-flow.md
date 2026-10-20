# Architecture and Data Flow

```mermaid
flowchart LR
 A[Human identities] --> E[Microsoft Entra ID]
 B[Workload identities] --> E
 C[Device identities] --> E
 E --> F[Authentication and access decisions]
 F --> G[Microsoft 365 services]
 G --> H[Exchange Online]
 G --> I[SharePoint and OneDrive]
 G --> J[Other connected services]
 E --> K[Sign-in logs]
 E --> L[Directory audit logs]
 H --> M[Workload audit activity]
 I --> M
 J --> M
 K --> N[Splunk ingestion]
 L --> N
 M --> N
 N --> O[Hunting and correlation]
 O --> P[Timeline and report]
```

## Sources seen in the evidence
| Sourcetype | Purpose | Important fields observed |
|---|---|---|
| `azure:aad:signin` | Authentication attempts | `userPrincipalName`, `ipAddress`, `appDisplayName`, `status.errorCode`, `clientAppUsed`, `conditionalAccessStatus` |
| `azure:aad:audit` | Identity/directory changes | `activityDisplayName`, `initiatedBy.user.userPrincipalName`, `initiatedBy.app.displayName`, `targetResources{}.userPrincipalName`, `result` |
| `o365:management:activity` | Workload activity | `Operation`, `UserId`, `ClientIP` / `ClientIPAddress`, `Workload`, `ObjectId` |

Field names vary by connector and extraction settings. Validate raw events, timestamp handling, normalization, retention, and collection coverage before building production detections.
