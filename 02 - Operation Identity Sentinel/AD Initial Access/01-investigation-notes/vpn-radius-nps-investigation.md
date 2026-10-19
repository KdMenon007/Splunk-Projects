# Investigation Notes — VPN Initial Access via RADIUS / NPS

## Purpose and scope
This evidence batch adds a third investigation path to Project 2: VPN authentication mediated by RADIUS and Windows Network Policy Server (NPS). Keep this path distinct from the IIS web-shell and Exchange/OWA paths unless host, source, account, and normalized timestamp correlation establishes a relationship.

## Authentication flow shown in the supplied diagram
1. A user attempts to connect through the VPN gateway.
2. The VPN gateway forwards authentication to NPS using RADIUS.
3. NPS validates the credentials/policy against the Active Directory environment (the diagram depicts LDAP communication with the domain controller).
4. NPS records the result, while Windows Security events may provide additional authentication context.

NPS events are expected only when the VPN gateway is configured to use RADIUS/NPS. If the VPN product authenticates directly against AD or another provider, this event path may not exist. Confirm the actual lab configuration before interpreting missing events as a gap or a clean result.

## Event IDs in the supplied notes
| Event ID | Meaning in the supplied material | Investigative use |
|---|---|---|
| 6272 | NPS granted access | Successful VPN authentication candidate |
| 6273 | NPS denied access | Failed VPN authentication candidate |
| 6274 | NPS discarded the request | Request/policy/configuration troubleshooting |
| 4624 | Windows logon succeeded | Contextual logon evidence; confirm host and logon type |
| 4625 | Windows logon failed | Failed authentication evidence; confirm host and status/substatus |
| 4776 | Credential validation | Potential NTLM credential-validation pivot; availability depends on authentication method and audit configuration |

The source notes describe NPS 6273 Reason Code 16 as unknown username/bad password, 48 as no matching network policy, and 65 as RADIUS shared-secret mismatch. Validate these values against the raw NPS event and the relevant Windows/NPS documentation for the installed version; a policy or shared-secret error is not equivalent to proof of malicious activity.

## Screenshot observations

### NPS denial distribution
The screenshot query is:

```spl
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

The captured result shows 12 events total across three accounts, all associated with `Client_IP_Address=10.5.10.200`:

- `david.chen`: 10 denials
- `liam.patel`: 1 denial
- `michelle.smith`: 1 denial

**Interpretation:** David Chen is the strongest account-level lead in this result set. The concentration could be consistent with repeated password failures, but it does not alone prove brute force; confirm the exact time span, NPS reason codes, VPN gateway identity, expected user behavior, and whether events represent unique attempts.

**Field caveat:** In the separate screenshot querying NPS 6273/6272 events with `User_Account_Name=david.chen`, the displayed table shows `-` for `user` and `User_Account_Name` on the result rows. This suggests a field extraction, field-name, or query-filter mismatch in the displayed evidence. Do not treat the 6272 row as a verified successful NPS event for David until the raw event confirms the account and result.

### Windows Security timeline for David Chen
The screenshot query is:

```spl
index=win EventCode IN (4624, 4625) user="david.chen"
| table _time, host, user, EventCode, Logon_Type
| sort _time
```

The captured timeline on host `THM-DC` shows ten Event ID 4625 rows from approximately `2026-02-12 10:46:01` through `10:47:00`, followed by one Event ID 4624 at approximately `10:47:05`. The displayed `Logon_Type` is 3.

**Interpretation:** Failed logons followed by a successful logon five seconds after the last displayed failure are a high-priority credential-attack lead. This does not by itself prove the failures were VPN attempts or that the success was caused by them. Correlate NPS timestamps, account fields, client/gateway identity, event status/substatus, and the same host/time window.

### NPS event cross-check
A screenshot using `index=win EventCode IN (6273,6272) User_Account_Name=david.chen` appears to return denial events and a final 6272 row, but the displayed account field is blank/dash. Treat this as an unresolved data-quality issue. Re-run without the account filter, inspect raw events, and identify the actual extracted account field before claiming an NPS success for this user.

## Investigation hypothesis
A possible sequence is repeated VPN credential failures associated with David Chen, followed by a successful Windows logon. The Windows timeline supports the failure-then-success pattern for the displayed account, but the NPS-to-Windows relationship is **not yet validated** because the supplied NPS result has an account-field mismatch and `Client_IP_Address` identifies the RADIUS client/gateway, not necessarily the original remote endpoint.

## Recommended pivots
1. Inspect raw NPS 6273 events and capture `User_Account_Name`, `Client_IP_Address`, `Reason_Code`, policy name, authentication type, and event time.
2. Confirm whether `10.5.10.200` is the configured VPN/RADIUS client in the lab; do not automatically treat it as the user's public source IP.
3. Query NPS 6272 and 6273 over a bounded window without account filters; compare the raw account fields and timestamps.
4. Inspect Windows 4624/4625 raw XML for `TargetUserName`, `IpAddress`, `WorkstationName`, `LogonType`, `Status`, `SubStatus`, and `AuthenticationPackageName` where available.
5. Correlate Event ID 4776 and relevant Kerberos events (4768, 4769, 4771) on the domain controller, accounting for the authentication protocol used.
6. After any confirmed successful authentication, examine logon session details, remote access, privileged-group changes, account changes, service/task creation, PowerShell, and access to file/SQL servers.
7. Compare activity to normal business hours, known VPN usage, and the user's baseline. Consider mistyped credentials, saved credentials, misconfigured clients, and automated services as alternatives.

## Confidence statement
- **High confidence in screenshot observations:** 12 NPS 6273 results grouped as 10/1/1 by the displayed fields; 10 Event ID 4625 rows followed by one 4624 for `david.chen` in the displayed timeline.
- **Moderate confidence in suspicion:** the failure cluster followed by success is consistent with a possible credential attack.
- **Not confirmed:** the NPS denials and Windows logons are the same authentication sequence; the 6272 is a verified successful NPS event for David; the activity is malicious; the environment suffered domain-wide compromise.

## Status
In progress. More raw events, exact NPS reason codes, the VPN gateway identity, and host/time correlation are required.
