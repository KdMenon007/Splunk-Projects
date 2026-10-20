# Sanitized Evidence Summary

The original 11 supplied screenshots are preserved in [`screenshots/`](screenshots/README.md) as evidence SS-01 through SS-11. The following records summarize the visible results. Review the screenshots for identifiers before publishing this repository publicly.

| ID | Source | Observation | Assessment |
|---|---|---|---|
| EV-01 | Entra sign-ins | Broad search returned 56 events | Confirms sign-in telemetry is present in the reviewed search window |
| EV-02 | Failed sign-ins | 26 events for one account/app/source IP; codes `50126`, `50140` | Worth investigating; not proof of password spraying or compromise |
| EV-03 | Successful sign-ins | 30 events from the same source-IP pivot; apps included `My Profile`, `My Signins`, `OfficeHome`, `One Outlook Web` | Source attribution and legitimacy remain unknown |
| EV-04 | Sign-in timeline | Earliest successful event shown: `2026-02-11 18:16:53`, `OfficeHome`, code `0` | Observed timestamp; actor attribution unverified |
| EV-05 | Audit, target-focused | 13 events; visible security-information registration, user updates, and password-reset operations | Validate actor and exact modified properties |
| EV-06 | Audit, actor-focused | 8 events, including self-service reset and security-information registration | Result sets may overlap; do not add counts as unique events |
| EV-07 | Exchange workload | 5 events between `18:18:10` and `18:20:09` on Feb 11 | Close temporal sequence after displayed sign-in; correlation still needs validation |
| EV-08 | Exchange operations | `New-InboxRule`, `Create`, `Send`, two `MailItemsAccessed` events | Rule action and message details are missing |
| EV-09 | Exchange source IPs | At least two source IP values shown | Could reflect client, proxy, or service infrastructure; investigate context |

## Sanitized timeline
| Timestamp shown | Source | Activity |
|---|---|---|
| 2026-02-11 18:16:53 | Entra sign-in | Successful `OfficeHome` sign-in |
| 2026-02-11 18:18:10 | Exchange | `New-InboxRule` |
| 2026-02-11 18:18:46 | Exchange | `Create` |
| 2026-02-11 18:19:39 | Exchange | `Send` |
| 2026-02-11 18:19:47 | Exchange | `MailItemsAccessed` |
| 2026-02-11 18:20:09 | Exchange | `MailItemsAccessed` |
| 2026-02-12 | Entra audit | Security-info registration and password-reset-related events |

## Caveats
- Counts are search-result counts, not guaranteed unique-event totals.
- Confirm timezone and original event time before final timeline claims.
- Feb 12 audit activity is a separate cluster unless event/session evidence links it to Feb 11.
- The visible rule description does not establish forwarding, deletion, or exfiltration.
