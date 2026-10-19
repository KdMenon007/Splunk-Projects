# Validation checklist

## Data readiness
- [ ] Confirm indexes, sourcetypes, hosts, and field names for IIS, Sysmon, and Windows Security.
- [ ] Verify ingestion delay and bounded time range.
- [ ] Normalize IIS UTC and Windows timestamps.
- [ ] Check whether client IPs represent the true source or a proxy/load balancer.
- [ ] Save raw events for each key finding.

## IIS / web-shell path
- [ ] Validate 404 count and time span.
- [ ] Inspect the request sequence for the suspicious source.
- [ ] Decode URL-encoded query strings.
- [ ] Confirm upload handler behavior and whether a file was written.
- [ ] Correlate Event ID 11 with POST and subsequent requests.
- [ ] Review file hash, metadata, ACLs, and application legitimacy.
- [ ] Correlate process creation by host and normalized time.
- [ ] Review csc.exe as possible ASP.NET compilation.

## OWA / credentials path
- [ ] Confirm OWA path and reason=2 behavior for the server version.
- [ ] Determine whether attempts target one account or many.
- [ ] Correlate IIS source with Windows events without assuming source IP is present in 4624/4625.
- [ ] Sort chronologically; verify whether success precedes or follows failures.
- [ ] Check post-login ECP/PowerShell and unusual mailbox activity.

## AD impact
- [ ] Review DC events 4768, 4769, 4771, 4776 and relevant 4624/4625 events.
- [ ] Review group changes, new accounts, password resets, and account changes.
- [ ] Scope remote logons, services, tasks, PowerShell, WMI, and lateral movement.
- [ ] Record benign explanations and telemetry gaps.


## VPN / RADIUS / NPS validation
- [ ] Confirm VPN gateway uses RADIUS/NPS in this lab.
- [ ] Confirm `10.5.10.200` is the expected RADIUS client/gateway.
- [ ] Inspect raw NPS 6272/6273 events and validate account, reason code, policy, and timestamp fields.
- [ ] Resolve the account-field mismatch shown in the NPS screenshot before correlating a grant with David Chen.
- [ ] Verify the 4625-to-4624 sequence in raw Windows Security events, including Logon Type, source IP/workstation, status/substatus, and authentication package.
- [ ] Correlate NPS and Windows timestamps in the same normalized time zone.
- [ ] Review 4776 and relevant Kerberos events where applicable.
- [ ] Document benign explanations and post-authentication activity before concluding compromise.
