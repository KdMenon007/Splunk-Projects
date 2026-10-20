# Operation Cloud Mailwatch
## Phase 1 — Microsoft 365 Monitoring Basics

**Focus:** Microsoft Entra ID identity telemetry, Microsoft 365 workload activity, Splunk SPL, and evidence-driven threat hunting.

Operation Cloud Mailwatch is an independent security monitoring project that investigates identity activity and traces potentially suspicious actions across Microsoft 365. The guiding rule is simple: **an unusual event is not automatically a confirmed incident.**

## Objectives
- Understand authentication, authorization, identity, and audit evidence.
- Hunt for concentrated failed sign-ins and successful sign-ins from the same source.
- Review identity audit events affecting or initiated by an account.
- Investigate Exchange workload activity, especially inbox-rule operations and mailbox access.
- Correlate evidence into a defensible timeline and document uncertainty.

## Phase 1 observed results
The reviewed Splunk screenshots show: **56** broad sign-in events; **26** failed sign-in events aggregated for one account/app/source IP with visible codes `50126` and `50140`; **30** successful events in a pivot for the same source; **13** target-focused audit events; **8** actor-focused audit events; and **5** Exchange workload events between `2026-02-11 18:18:10` and `18:20:09`. Visible Exchange operations were `New-InboxRule`, `Create`, `Send`, and two `MailItemsAccessed` events.

These are search-result counts, not necessarily unique-event counts. The sequence warrants further investigation but does not prove account compromise, malicious inbox-rule behavior, or exfiltration. See [the report](reports/phase-1-threat-hunting-report.md) and [evidence register](evidence/observed-results.md).

## Repository map
- `docs/` — fundamentals, architecture, telemetry, methodology
- `diagrams/` — Mermaid source diagrams
- `spl/` — reusable search starting points
- `reports/` — Phase 1 report and incident template
- `evidence/` — observed results, conceptual illustrations, and all 11 supplied screenshots with an evidence index
- `templates/` — repeatable hunt template
- `references/` — field dictionary

## Run the searches
1. Confirm your index, sourcetypes, time range, and timezone.
2. Replace `$USER_UPN$` and `$SOURCE_IP$` placeholders.
3. Validate field extraction against raw events, especially nested fields.
4. Record the query, result count, time range, and validation status.
5. Keep observed facts separate from interpretation.

The SPL examples use the index and sourcetypes observed in the supplied evidence. Adapt them to your connector and schema before production use.

## Data hygiene
All 11 supplied screenshots are included under `evidence/screenshots/`, with descriptive filenames and an evidence index. They are preserved unchanged and may show lab account, tenant, source-IP, or host details; review/redact identifiers before making the repository public. Never commit credentials, tokens, secrets, or identifiers you are not authorized to disclose.

## Status
Phase 1 documentation, initial SPL library, Mermaid diagrams, evidence-qualified report, and all 11 supplied screenshots with an evidence register are included. The exact inbox-rule action, actor/session context, source-IP attribution, and user intent remain unverified.
