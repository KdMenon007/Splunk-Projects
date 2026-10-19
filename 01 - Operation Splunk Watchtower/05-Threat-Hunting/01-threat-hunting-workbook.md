# Splunk Threat Hunting — Hands-on Workbook

## Objective
Use SPL to baseline URI, username, and source-IP activity, then investigate access to `secret-document.pdf`. This is a lab investigation, not a claim that observed activity is malicious.

## 1. Confirm data and time range
Select a time range that covers the lab data and run:
```spl
index="main"
```
If no events appear, verify the time picker, index, sourcetype, host, and source. The supplied notes use `index="main"`; the screenshots show network-style events and a `[Network-log]` marker.

## 2. URI baseline
```spl
index="main"
| stats count by URI
| sort - count
```
Question: which resources are most common? Is `secret-document.pdf` present? A high count alone is not malicious.

## 3. Username baseline
```spl
index="main"
| stats count by Username
| sort - count
```
The screenshots show `Robert Wilson` prominent in one sample result. Re-run against the current data rather than assuming the same ranking.

## 4. Source-IP baseline
```spl
index="main"
| stats count by SourceIP
| sort - count
```
Screenshots contain private-range examples such as `10.0.0.x`, `172.16.0.x`, and `192.168.1.x`. Private IPs are not inherently safe or malicious; map them to expected lab systems.

## 5. Search for sensitive-document access
```spl
index="main" "secret-document.pdf"
```
For each hit, record timestamp, username, department, source IP, URI, country (if extracted), and response status if present. Inspect raw events and surrounding activity. A file request alone does not prove exfiltration; check success/failure, repeated access, volume, user role, and related events.

## 6. Pivot on values observed in results
Replace placeholders with actual values from your search:
```spl
index="main" Username="REPLACE_WITH_USER"
| sort - _time
```
```spl
index="main" SourceIP="REPLACE_WITH_IP"
| stats count by Username URI Country
| sort - count
```
```spl
index="main" "secret-document.pdf"
| table _time Username Department SourceIP URI Country host source sourcetype
| sort - _time
```
If fields are missing, verify field extraction and capitalization. `table` displays fields; it does not extract them.

## 7. Event-boundary validation
A screenshot shows this example:
```ini
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Network-log\]
```
This is suitable only if each intended event begins with `[Network-log]`. Test on a lab sourcetype first. Parsing/event-breaking changes generally do not repair already-indexed events.

## Investigation notes
- Hypothesis:
- Time range:
- Index / sourcetype:
- Observed event(s):
- User / department:
- Source IP:
- Requested URI:
- Evidence supporting concern:
- Benign explanations checked:
- Next pivot:
- Conclusion: confirmed / suspicious / benign / inconclusive
- Confidence and reason:

## Completion checklist
- [ ] Verified index and time range.
- [ ] Ran URI, username, and source-IP baselines.
- [ ] Searched for `secret-document.pdf`.
- [ ] Inspected raw events.
- [ ] Pivoted on a user or source IP.
- [ ] Checked extracted fields.
- [ ] Separated evidence from assumptions.
