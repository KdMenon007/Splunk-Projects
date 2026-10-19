# SPL Query Cookbook — AD Initial Access

Before running, confirm index/sourcetype/field names, replace example IPs/usernames, and use a bounded time range. These are defensive investigation searches for an authorized lab.


## VPN / RADIUS / NPS investigation

- `14-nps-denials-by-user-client.spl` — scope NPS denial events by account and RADIUS client.
- `15-nps-results-user-timeline.spl` — inspect NPS grants and denials without filtering on a possibly mis-extracted account field. Confirm field names against raw events.
- `16-windows-authentication-timeline-david-chen.spl` — examine the visible failure-then-success sequence and supporting Windows fields.
- `17-nps-reason-code-breakdown.spl` — group denials by the available reason-code field.
- `18-ntlm-credential-validation-4776.spl` — pivot into NTLM credential validation where applicable.
- `19-dc-kerberos-authentication-pivots.spl` — review Kerberos authentication events where applicable.

**Field caveat:** The supplied screenshots show `User_Account_Name` and `user` behaving inconsistently for NPS events. If the search returns blanks or misses expected rows, remove account filters, inspect raw events, and substitute the field names present in your actual data. `Client_IP_Address` is the RADIUS client address in this context, often the VPN gateway—not necessarily the remote user's originating IP.


## IIS `error.aspx` threat-hunting scenario (separate evidence stream)

Queries `20`–`24` cover 404 source counts, successful URI distribution, command-like query strings, the upload POST, and Sysmon Event ID 11 file creation. See `../01-investigation-notes/iis-error-aspx-threat-hunting-scenario.md`. The screenshot IP `198.51.100.23` is documentation-range data; do not combine this scenario with the earlier `shell.aspx` evidence without raw-event correlation.
