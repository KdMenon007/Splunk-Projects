# Architecture, Detection Logic & Investigation Workflows (Mermaid Diagrams)

This document contains GitHub-renderable Mermaid diagrams modeling the Entra ID telemetry pipeline, observed attack timelines, detection decision trees, and SOC triage workflows for **Operation Cloud Mailwatch**.

---

## 1. Entra ID Telemetry Ingestion & Splunk Detection Architecture

```mermaid
flowchart LR
    subgraph EntraID["Microsoft Entra ID (finegalo.thm)"]
        L1["Sign-In Logs"]
        L2["Identity Protection<br/>Risky Users"]
        L3["Directory Audit Logs"]
    end

    subgraph SplunkIngest["Splunk Ingestion & Sourcetypes"]
        ST1["azure:aad:signin"]
        ST2["azure:aad:identity_protection:risky_user"]
        ST3["azure:aad:audit"]
    end

    subgraph Detections["SPL Analytics & Hunting Rules"]
        D1["01: Password Spray &<br/>Throttling Brute Force"]
        D2["02: Risky User &<br/>CAP Block Enforcement"]
        D3["03: MFA Fatigue &<br/>Country Baseline Pivot"]
        D4["04: Rogue User, Role Escalation<br/>& MFA Device Persistence"]
        D5["05: OAuth Consent &<br/>Mail.Read.All Exposure"]
    end

    L1 --> ST1 --> D1 & D2 & D3
    L2 --> ST2 --> D2
    L3 --> ST3 --> D4 & D5
```

---

## 2. Module 01 — Password Attack Classification & Compromise Pivot Flowchart

Based on `index="task-2"` (`22` failed sign-in events with `status.errorCode=50126` on `OfficeHome`):

```mermaid
flowchart TD
    Start["Filter Entra ID Sign-In Logs<br/>status.errorCode!=0 AND conditionalAccessStatus!=success<br/>(22 Total Failed Events)"]
    GroupIP["Aggregate by ipAddress<br/>dc(userPrincipalName) & count(failures)"]

    Spray{"High Distinct Users<br/>(targeted_accounts > 1)?"}
    Brute{"Single Target User<br/>(targeted_accounts = 1)<br/>with Repeated Failures?"}

    SprayHit["Password Spraying Confirmed<br/>IP: 94.20.222.248 (AZ)<br/>7 Targeted Users | 14 Failures (2 per user)"]
    BruteHit["Throttling Brute Force Confirmed<br/>IP: 38.165.231.218 (MX)<br/>Target: amanda.costa@finegalo.thm (4 Failures)"]
    OtherIPs["Secondary Single-Account IPs<br/>149.102.234.27 (BR -> andre.oliveira): 2 failures<br/>2804:2488:7082:a4c0:901:9e5d:4cd7:ff0e (allan.smith): 2 failures"]

    Pivot["Pivot to Successful Logins<br/>status.errorCode=0 for amanda.costa@finegalo.thm"]
    Compromised["Compromise Verified<br/>3 Successful Logins from 38.165.231.218"]

    Start --> GroupIP
    GroupIP --> Spray
    Spray -- Yes --> SprayHit
    Spray -- No --> Brute
    Brute -- Yes --> BruteHit --> Pivot --> Compromised
    Brute -- No --> OtherIPs
```

---

## 3. Observed Incident Timeline (2026-02-25 to 2026-03-04)

```mermaid
timeline
    title Entra ID Attack & Compromise Progression (finegalo.thm)
    2026-02-25 12:33 - 12:34 : Password Spraying (94.20.222.248 / AZ)
                             : 14 failed logins (Error 50126) across 7 accounts on OfficeHome
    2026-02-25 12:35 : Secondary Failed Attempts (149.102.234.27 / BR)
                     : 2 failed logins against andre.oliveira@finegalo.thm
    2026-02-25 12:39 - 13:00 : Throttling Brute Force (38.165.231.218 / MX)
                             : 4 paced failed attempts against amanda.costa@finegalo.thm -> 3 successful logins
    2026-03-03 12:51 - 13:31 : Conditional Access Enforcement
                             : Block Suspicious Countries blocked 6 OfficeHome attempts for Allan Senna (94.20.222.248 & 94.20.222.251)
    2026-03-03 19:46 : Identity Protection Risk Flag
                     : allan.senna@finegalo.thm marked riskLevel=high / riskState=atRisk
    2026-03-04 12:30 - 13:26 : MFA Fatigue & Compromise (igor.bicalho@finegalo.thm)
                             : 10 MFA denials (Error 500121) from 149.102.234.27 (BR) -> successful login at 13:26:22 (baseline: 96.0.24.134 / DK)
    2026-03-04 13:31 - 13:36 : Privilege Escalation & Persistence
                             : igor.bicalho@finegalo.thm created rafael.maciel@finegalo.thm (13:31:48), assigned Global Administrator (13:31:49), and added MFA device (13:36)
```

---

## 4. SOC Analyst Incident Response & Containment Workflow

```mermaid
flowchart TD
    Alert["Alert Triggered in Splunk<br/>(Spray / Brute Force / MFA Fatigue / Privileged Change)"]
    Triage{"Did a Successful Login<br/>(status.errorCode=0) or<br/>Audit Change Occur?"}

    BlockOnly["Contain Source Infrastructure<br/>1. Block attacker IP / ASN in Conditional Access<br/>2. Monitor targeted accounts for follow-up sprays"]

    IR1["1. Immediate Identity Containment<br/>Revoke Entra ID refresh tokens & active sessions<br/>Reset passwords for compromised users (amanda.costa, igor.bicalho)"]
    IR2["2. Eradicate Persistence<br/>Disable/delete rogue user (rafael.maciel@finegalo.thm)<br/>Remove unauthorized Global Administrator role (TenantAdmins)<br/>Delete unauthorized MFA / security info methods"]
    IR3["3. Audit OAuth & Mailbox Exposure<br/>Review Consent to application audit logs<br/>Revoke suspicious apps with Mail.Read.All"]

    Alert --> Triage
    Triage -- No --> BlockOnly
    Triage -- Yes --> IR1 --> IR2 --> IR3
```
