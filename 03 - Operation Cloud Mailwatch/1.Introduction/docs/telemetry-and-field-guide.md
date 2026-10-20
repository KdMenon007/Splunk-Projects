# Telemetry and Field Guide

## Sign-in fields
| Field | Use | Caution |
|---|---|---|
| `userPrincipalName` | Identify account | Redact in public evidence |
| `_time` / `createdDateTime` | Timeline | Confirm timezone and ingestion delay |
| `ipAddress` | Pivot across events | VPNs, proxies, carrier networks, and shared egress complicate attribution |
| `appDisplayName` | Application context | Known app name does not prove legitimacy |
| `status.errorCode` | Authentication result | Interpret alongside full event details |
| `clientAppUsed` | Client context | Schema/field extraction may vary |
| `conditionalAccessStatus` | Policy outcome | Inspect policy details where available |

In the reviewed dataset, `status.errorCode=0` was used for success and non-zero codes for failures. Validate this interpretation against your event schema. Error codes `50126` and `50140` were visible; investigate their full context rather than treating a code alone as proof of an attack.

## Audit fields
- `activityDisplayName`: recorded action.
- `initiatedBy.user.userPrincipalName`: user actor, if present.
- `initiatedBy.app.displayName`: application actor, if present.
- `targetResources{}.userPrincipalName`: target identity.
- `targetResources{}.modifiedProperties`: changed properties, when present.
- `result`: operation outcome.

Actor and target are not interchangeable. An application can initiate a change to a user.

## Microsoft 365 activity fields
- `Operation`: service operation, such as `New-InboxRule` or `MailItemsAccessed`.
- `UserId`: associated account.
- `ClientIP` / `ClientIPAddress`: source field varies.
- `Workload`: workload name.
- `ObjectId`: object identifier or description.

For a rule-creation event, inspect the full rule parameters and actions. The operation name alone does not establish forwarding, deletion, or exfiltration.
