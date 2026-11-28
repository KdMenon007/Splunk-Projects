# Exchange Online Monitoring & Threat Hunting Project (v4)

## Overview
Exchange Online monitoring and incident investigation package covering **Initial Access**, **Inbox Rule & Mailbox Forwarding Abuse**, and **Compromised Account Phishing** in Splunk (`One Outlook Web` sign-ins, `Workload=Exchange` audit logs, and `o365:reporting:messagetrace`).

## Architecture & Investigation Flow

```mermaid
flowchart TD
    subgraph Telemetry["1. Log Sources"]
        L1["Entra ID Sign-In Logs"]
        L2["M365 Unified Audit Logs"]
        L3["Message Trace Logs"]
    end

    subgraph Detection["2. Core Monitoring Areas"]
        D1["Mailbox Access and Sign-In Review"]
        D2["Inbox Rules and Mailbox Forwarding"]
        D3["Outbound Phishing and Replies"]
    end

    subgraph Response["3. Triage and Containment"]
        R1["Correlate Timeline"]
        R2["Remove Rules and Forwarding"]
        R3["Contain Account and Scope Victims"]
    end

    L1 --> D1
    L2 --> D2
    L3 --> D3
    D1 --> R1
    D2 --> R1
    D3 --> R1
    R1 --> R2 --> R3
```

## Included Files
* `charts/exchange_activity_summary.png` — Visual chart of query event counts and Robert Green compromise sequence
* `evidence/screenshots/` — Actual captured Splunk screenshots (`01` through `07`)
* `evidence/investigation_findings.md` — Embedded screenshot references, case findings, and timeline notes
* `detections/exchange_monitoring_queries.spl` — Splunk SPL queries
* `playbooks/exchange_compromise_triage.md` — Incident response playbook
* `dashboards/exchange_monitoring_dashboard.json` — Dashboard panel queries
