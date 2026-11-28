# Operation Cloud Mailwatch — Entra ID Identity-Threat Monitoring

A security monitoring, threat-hunting, and incident response portfolio project focused on detecting and investigating identity-based attacks against **Microsoft Entra ID** (`finegalo.thm`) using **Splunk**.

---

## Project Overview

| Attribute | Details |
| :--- | :--- |
| **Project Name** | Operation Cloud Mailwatch |
| **Target Environment** | Microsoft Entra ID (Azure AD) — Tenant `finegalo.thm` |
| **SIEM Platform** | Splunk |
| **Project Focus** | Identity-Threat Detection, Threat Hunting & Incident Response |
| **Current Stage** | Phase 2 — Complete SPL Query Pack & Splunk Evidence Integration |

---

## End-to-End Attack Kill Chain & Detection Architecture

The diagram below models the full identity intrusion lifecycle observed across the investigated Entra ID telemetry—from external password-based attacks and MFA fatigue through account takeover, privilege escalation, persistence, and OAuth application exposure—mapped to the Splunk log sources and detections in this repository.

flowchart TD
    subgraph External["1. Initial Access & Credential Attacks"]
        A1["Password Spraying: 94.20.222.248 (AZ) - 7 users / 14 failures (Error 50126)"]
        A2["Throttling Brute Force: 38.165.231.218 (MX) - amanda.costa@finegalo.thm (4 failures)"]
        A3["Risky Sign-In: 94.20.222.251 to allan.senna@finegalo.thm - Blocked by CAP"]
        A4["MFA Fatigue: 149.102.234.27 (BR) to igor.bicalho@finegalo.thm - 10 denials (Error 500121)"]
    end

    subgraph Compromise["2. Account Compromise & Baseline Deviation"]
        B1["amanda.costa@finegalo.thm: 3 successful logins (Error 0) from 38.165.231.218"]
        B2["igor.bicalho@finegalo.thm: Baseline 96.0.24.134 (DK), Compromise 149.102.234.27 (BR) at 2026-03-04 13:26:22"]
    end

    subgraph Persistence["3. Privilege Escalation & Persistence (Audit Logs)"]
        C1["Rogue Account Created (13:31:48.764): Add user by igor.bicalho@finegalo.thm to rafael.maciel@finegalo.thm"]
        C2["Privilege Escalation (13:31:49.154): Add member to Global Administrator by igor.bicalho@finegalo.thm"]
        C3["MFA Persistence (13:36): Security info registration (Add)"]
    end

    subgraph OAuth["4. Cloud Application & OAuth Abuse Vector"]
        D1["Consent to application: High-Impact Graph Permission Mail.Read.All"]
    end

    subgraph Splunk["Splunk Detection & Hunting Layer"]
        S1["azure:aad:signin (Modules 01, 02, 03)"]
        S2["azure:aad:identity_protection:risky_user (Module 02)"]
        S3["azure:aad:audit (Modules 04, 05)"]
    end

    A2 --> B1
    A4 --> B2
    B2 --> C1
    C1 --> C2
    C2 --> C3

    A1 --> S1
    A2 --> S1
    A3 --> S1
    A4 --> S1
    B1 --> S1
    B2 --> S1

    A3 --> S2

    C1 --> S3
    C2 --> S3
    C3 --> S3
    D1 --> S3

---

## Threat Coverage & Investigation Findings

| Module | Threat Domain | Key Telemetry & Observed Findings | Validation Status |
| :--- | :--- | :--- | :--- |
| **01** | **Password-Based Attacks** | • **Password Spray:** `94.20.222.248` (`AZ`) targeted **7 unique accounts** with **14 failed attempts** (`status.errorCode=50126`, 2 failures per user).<br>• **Throttling Brute Force & Compromise:** `38.165.231.218` (`MX`) targeted `amanda.costa@finegalo.thm` with **4 failed attempts** followed by **3 successful logins** (`status.errorCode=0`). | **Validated (4 Splunk Screenshots)** |
| **02** | **Conditional Access & Identity Protection** | • **Risky User:** `allan.senna@finegalo.thm` flagged in Identity Protection (`riskLevel=high`, `riskState=atRisk`, event time `2026-03-03 19:46:39`, `anonymizedIPAddress` risk context).<br>• **Conditional Access Enforcement:** Policy **`Block Suspicious Countries`** blocked **6 sign-in attempts** (`conditionalAccessStatus=failure`) to `OfficeHome` (`5` from `94.20.222.251` between `13:30:26`–`13:31:16` and `1` from `94.20.222.248` at `12:51:53`). | **Validated (2 Splunk Screenshots)** |
| **03** | **MFA Bypass Techniques** | • **MFA Fatigue Attack:** `igor.bicalho@finegalo.thm` targeted from `149.102.234.27` (`BR`) with **10 consecutive MFA prompt denials** (`status.errorCode=500121`) between `12:30:06` and `13:24:13`.<br>• **Geographic Baseline & Compromise:** User baseline sign-ins originated from `96.0.24.134` in **Denmark (`DK`)**; attacker achieved a successful login (`status.errorCode=0`) from `149.102.234.27` (**Brazil (`BR`)**) at `2026-03-04 13:26:22`. | **Validated (3 Splunk Screenshots)** |
| **04** | **Privilege Escalation & Persistence** | • **Account Creation (`2026-03-04 13:31:48.764`):** Compromised actor `igor.bicalho@finegalo.thm` executed `Add user` to create `rafael.maciel@finegalo.thm`.<br>• **Role Elevation (`2026-03-04 13:31:49.154`):** `igor.bicalho@finegalo.thm` executed `Add member to role` assigning **`Global Administrator`** (`62e90394-69f5-4237-9190-012177145e10` / `TenantAdmins`) to `rafael.maciel@finegalo.thm`.<br>• **MFA Persistence (`2026-03-04 13:36`):** `User started security info registration` (`operationType="Add"`) recorded. | **Validated (2 Splunk Screenshots)** |
| **05** | **OAuth Application Abuse** | • **Audit Monitoring:** Tracking `activityDisplayName="Consent to application"` in `azure:aad:audit`.<br>• **High-Risk Scope Focus:** Detecting tenant-wide mailbox read exposure via **`Mail.Read.All`**. | Detection Logic Documented |

---

## Repository Structure

```text
operation-cloud-mailwatch-entra-id-monitoring/
│
├── README.md                                              # Project landing page, kill-chain diagram & findings summary
├── BUILD-STATUS.md                                        # Phased build tracker and validation matrix
│
├── docs/
│   ├── 01-entra-id-monitoring-source.md                   # Preserved source investigation notes (unmodified)
│   └── architecture-and-workflows.md                      # Mermaid diagrams: kill chain, detection pipeline & SOC workflows
│
├── detections/
│   └── splunk/
│       ├── README.md                                      # SPL detection index & validation policy
│       ├── all-detections.spl                             # Consolidated, runnable SPL query pack (Modules 01–05)
│       ├── 01-password-based-attacks.md                   # Password spray, throttling brute force & compromise pivot SPL
│       ├── 02-conditional-access-identity-protection.md   # Risky user & Conditional Access failure SPL
│       ├── 03-mfa-bypass-techniques.md                    # MFA fatigue (500121) & baseline country deviation SPL
│       ├── 04-privilege-escalation-persistence.md         # Rogue user, Global Admin assignment & MFA registration SPL
│       └── 05-oauth-application-abuse.md                  # Application consent & high-risk Graph permission SPL
│
├── investigation-playbooks/
│   └── README.md                                          # Step-by-step SOC analyst triage & containment playbooks
│
├── evidence/
│   └── screenshots/
│       ├── README.md                                      # Complete screenshot inventory and query mapping (11 captures)
│       ├── 01-password-attacks-failed-signins-timeline.png
│       ├── 01-password-spray-ip-aggregation.png
│       ├── 01-throttling-bruteforce-per-user-ip.png
│       ├── 01-throttling-bruteforce-compromise-pivot.png
│       ├── 02-risky-user-identity-protection.png
│       ├── 02-conditional-access-block-suspicious-countries.png
│       ├── 03-mfa-fatigue-500121-summary.png
│       ├── 03-mfa-baseline-country-signins.png
│       ├── 03-mfa-fatigue-dk-to-br-timeline.png
│       ├── 04-rogue-user-creation-audit.png
│       └── 04-privileged-role-assignment-audit.png
│
└── references/
    └── README.md                                          # Entra ID schemas, error codes, CIM & MITRE ATT&CK mapping
```
