# Screenshot Evidence Index

This directory preserves all 11 screenshots supplied for Phase 1. Filenames are descriptive; the source images have not been altered. The two architecture/access-control illustrations are conceptual, while the remaining images show Splunk search results.

> **Public repository note:** These screenshots visibly contain lab-style account, tenant, source-IP, and/or Splunk host details. Review and redact any identifiers you do not want public before pushing this repository to GitHub. Do not treat IP addresses or event names alone as proof of an individual attacker or compromise.

| Evidence ID | Screenshot | What it supports |
|---|---|---|
| SS-01 | [`01-entra-id-identity-architecture.png`](01-entra-id-identity-architecture.png) — **Microsoft Entra ID identity architecture illustration** | Conceptual diagram showing workforce, external and workload identities connecting through Entra ID to SaaS, cloud infrastructure, devices, on-premises applications, and Active Directory. |
| SS-02 | [`02-conditional-access-login-signals.png`](02-conditional-access-login-signals.png) — **Authentication signals and access decisions** | Conceptual flow of user/location, device, application and real-time risk signals into access decisions, including allow, require MFA, or block. |
| SS-03 | [`03-signin-event-overview.png`](03-signin-event-overview.png) — **Broad Entra ID sign-in search results** | Splunk search for azure:aad:signin events; screenshot shows 56 events in the selected search window. |
| SS-04 | [`04-failed-signin-aggregation.png`](04-failed-signin-aggregation.png) — **Failed sign-ins aggregated by user, application, source IP and error code** | SPL aggregation screenshot showing 26 events, OfficeHome, and error codes 50126 and 50140 for the account/source pivot shown. |
| SS-05 | [`05-successful-signin-source-pivot.png`](05-successful-signin-source-pivot.png) — **Successful sign-ins from the source IP** | Successful sign-in pivot showing 30 events and application names including My Profile, My Signins, OfficeHome, and One Outlook Web. |
| SS-06 | [`06-first-successful-signin-timeline.png`](06-first-successful-signin-timeline.png) — **Earliest successful sign-in displayed** | Timeline query screenshot showing a successful OfficeHome sign-in at 2026-02-11 18:16:53 with error code 0. |
| SS-07 | [`07-audit-events-targeting-user.png`](07-audit-events-targeting-user.png) — **Audit events targeting the account** | Audit-log query screenshot showing 13 events, including password-reset and security-information-related activities. |
| SS-08 | [`08-audit-events-initiated-by-user.png`](08-audit-events-initiated-by-user.png) — **Audit events initiated by the account** | Actor-focused audit query screenshot showing 8 events, including self-service password-reset and security-information registration activities. |
| SS-09 | [`09-exchange-workload-activity.png`](09-exchange-workload-activity.png) — **Exchange Online workload activity** | Five Exchange workload events including New-InboxRule, Create, Send, and MailItemsAccessed. |
| SS-10 | [`10-mail-items-accessed-event-detail.png`](10-mail-items-accessed-event-detail.png) — **MailItemsAccessed event pivot** | Focused query showing one MailItemsAccessed event from the selected source IP, at 2026-02-11 18:20:09 as displayed. |
| SS-11 | [`11-m365-management-activity-overview.png`](11-m365-management-activity-overview.png) — **Microsoft 365 management activity event overview** | Overview of six o365:management:activity events in the selected search window. |

## Evidence interpretation

- Event counts are search-result counts and may not represent unique events.
- Timestamps are reproduced as shown in the supplied screenshots; timezone context should be confirmed in Splunk.
- The evidence supports further investigation of authentication and mailbox activity, but does not by itself confirm account compromise, malicious inbox-rule behavior, or data exfiltration.
- Original query syntax and result counts should be revalidated against the active index, sourcetypes, time range, and field extraction before reuse.
