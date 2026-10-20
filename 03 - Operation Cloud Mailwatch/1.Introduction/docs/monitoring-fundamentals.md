# Microsoft 365 Monitoring Fundamentals

## Identity is broader than a user
A digital identity may represent a person, device, or workload such as an application or service. Machine identities can possess privileges and must be monitored alongside human accounts.

## Authentication, authorization, and auditing
| Concept | Question | Example evidence |
|---|---|---|
| Authentication | Who or what authenticated? | Sign-in result, source IP, application, device |
| Authorization | What can it access? | Roles, group membership, application permissions |
| Auditing | What happened? | Actor, target, activity, outcome, timestamp |

**Authentication success does not prove that the account owner was behind the session, nor that later actions were benign.**

## Identity provider and SSO
Microsoft Entra ID can centralize identity and authentication for connected applications. Single sign-on reduces credential sprawl and enables consistent use of MFA, Conditional Access, and centralized logging. Centralization also makes identity controls high-value targets.

## Controls worth monitoring
- MFA requirement and result; authentication-method registration or changes.
- Conditional Access policies and outcomes.
- Risky sign-ins and risky users where available.
- Privileged role assignments, group membership, and application permissions.
- Account lifecycle events and access revocation.
- Logging coverage, retention, and ingestion delays.

A control existing is not the same as being correctly configured, enforced, and logged.

## Cross-service investigation
Use identity events to establish how access occurred, audit events to determine what changed, and service activity to investigate what was done. Correlate by identity, timestamp, source IP, session/correlation ID, application, and target object where available.
