# SPL Query Library --- Exploring SPL

**Dataset referenced in the supplied screenshots:** `windowslogs`\
**Important:** Run these in the authorized lab. Field availability and
event counts depend on the actual dataset and time range.

## 1. Filter by source IP

``` spl
index="windowslogs" SourceIp="172.90.12.11"
```

Filters events to the specified source IP. The screenshot shows **53
events** for the displayed search/time range.

## 2. Exclude SYSTEM account

``` spl
index=windowslogs AccountName!=SYSTEM
```

Returns events where `AccountName` is not `SYSTEM`. Confirm that
`AccountName` is populated and that the intended case/field semantics
match the dataset.

## 3. Combine account conditions

``` spl
index=windowslogs AccountName!=SYSTEM AccountName=James
```

The adjacent conditions are combined as an AND in the search. The source
notes also show an explicit `AND` version:

``` spl
index=windowslogs AccountName!=SYSTEM AND AccountName=James
```

These conditions may be logically redundant or contradictory depending
on how `AccountName` is populated; validate the expected result before
treating it as a useful hunt.

## 4. Destination IP and port

``` spl
index=windowslogs DestinationIp="172.18.39.6" DestinationPort=135
```

Filters to the destination IP and port. The screenshot shows **4
events** for the displayed search/time range. Port 135 is commonly
associated with Microsoft RPC endpoint mapping, but the screenshot alone
does not establish malicious activity.

## 5. Select fields and deduplicate source IPs

``` spl
index=windowslogs
| fields EventID User Image Hostname SourceIp
| dedup SourceIp
```

Keeps a smaller field set and one result per `SourceIp`. `dedup` retains
one event per distinct value according to the current result ordering;
choose a deliberate sort/order if the representative event matters.

## 6. Rename User to Employee

``` spl
index=windowslogs
| fields EventID User Image Hostname SourceIp
| rename User AS Employee
```

Renames `User` in the output pipeline. Check the actual capitalization
of field names in the dataset.

## 7. Filter executable image paths with regex

``` spl
index=windowslogs
| regex Image="\\.exe$"
```

Matches `Image` values ending in `.exe`. This is a field-value regular
expression; validate escaping and field values in the installed Splunk
version/data.

## 8. Find TargetObject values ending in Manager

``` spl
index=windowslogs
| regex TargetObject="Manager$"
| top limit=20 TargetObject
```

Filters `TargetObject` values whose text ends with `Manager`, then ranks
frequent values. The supplied note identifies
`HKLM\\SOFTWARE\\Microsoft\\SecurityManager` as the value with the most
results in the displayed output. The screenshot shows 139 events before
aggregation; confirm the top-value count in the result table if needed.

## 9. Build a compact event table

``` spl
index=windowslogs
| table _time EventID Hostname SourceName
```

Displays only the listed fields. Missing fields can appear blank;
confirm their names against the field sidebar.

## 10. Reverse a table's current result order

``` spl
index=windowslogs Hostname="Salena.Adam"
| table _time Hostname EventID Category
| reverse
```

The source notes show this pattern. `reverse` flips the current result
order; it does not independently guarantee chronological ordering. If
chronological order is required, explicitly sort by `_time`.

## 11. Correlate process creation and logon events with join

``` spl
index=windowslogs EventID=1
| join LogonId [
    search index=windowslogs EventID=4624
    | rename TargetLogonId AS LogonId
    | fields LogonId LogonType IpAddress
]
| table _time Image User LogonType IpAddress
```

This screenshot demonstrates a `join` pattern between process events and
logon events. Validate the join key, cardinality, and whether `LogonId`
and `TargetLogonId` are genuinely equivalent in this dataset. `join` can
be expensive and may drop unmatched events; for production-scale
correlation, evaluate alternatives such as `stats` or `transaction`
where appropriate.

## 12. Inspect process parent/child command lines

``` spl
index=windowslogs EventID=1
| table _time ParentProcessId ProcessId ParentCommandLine CommandLine
| reverse
```

Shows process lineage-related fields in a table. The screenshot includes
command-line activity resembling `net user /add ...`. Treat that as an
investigative lead; corroborate with account-management events, process
metadata, user context, and the outcome before concluding an account was
created.

## 13. Highlight selected fields/terms

``` spl
index=windowslogs
| highlight User EventID Image "Process accessed"
```

The supplied screenshot shows this `highlight` example. This is for
visual emphasis in search results, not a detection or filtering command.

## 14. Count events by EventID

``` spl
index=windowslogs
| stats count BY EventID
| sort EventID
```

Aggregates events by `EventID` and sorts by EventID. Useful for initial
telemetry profiling.

## 15. Timechart by image

``` spl
index=windowslogs Image!=""
| timechart span=30m count BY Image limit=5
```

Plots event counts in 30-minute buckets for up to five Image series.
High-cardinality fields can make visualizations noisy; consider
filtering known system activity or grouping by process name if the data
supports it.

## 16. Count EventID 4624

``` spl
index=windowslogs EventID=4624
```

The supplied screenshot shows **26 events** for the displayed
search/time range. Windows Security Event ID 4624 is generally a
successful logon event; verify the data source and event mapping before
interpreting it.

## Query validation checklist

-   Confirm index, sourcetype, time range, and field names.
-   Record the exact SPL and screenshot of results.
-   Capture event counts and notable field values with the time range.
-   Distinguish raw event counts from aggregated rows.
-   Do not infer maliciousness from a port, event ID, or command string
    alone.
-   Re-run after changing a query and update the report with the actual
    result.

## 17. Enrich process-image events with a risk-score lookup

**Evidence:** `../screenshots/21-image-risk-score-lookup.png`

```spl
index=windowslogs
| lookup image_riskscore Image OUTPUT RiskScore
| stats count by Image RiskScore
| sort - RiskScore
```

**What it does**

1. Searches events in `windowslogs`.
2. Uses the configured lookup named `image_riskscore`, matching the event's `Image` field to the lookup's `Image` key and adding `RiskScore`.
3. Aggregates event counts for each `Image` and `RiskScore` pair.
4. Sorts the output by descending `RiskScore`.

**Screenshot observation:** the search UI shows 12,256 events in the event view, and the `Image` field summary lists 35 values (34.497% of events). The screenshot does not show the full statistics table or lookup definition, so it does not establish which image has the highest risk score or whether every event matched the lookup.

**Validation notes:** confirm the lookup exists, its key field is named `Image`, its output field is `RiskScore`, and score values are numeric if numeric ordering is intended. Events with no lookup match may have a null `RiskScore`; decide how to handle unmatched images before using this as a detection or prioritization rule. A lookup score is only as useful as its source, coverage, and maintenance.

## 18. Detect VPN login times that differ from a user's historical pattern

**Evidence:** `../screenshots/22-vpn-login-hour-zscore-anomaly.png`

```spl
index=vpnlogs
| eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
| eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
| eval zscore=abs(hour - typical_hour) / stdev_hour
| where zscore > 3
| eval hour=round(hour, 2), typical_hour=round(typical_hour, 2)
| eval stdev_hour=round(stdev_hour, 2), zscore=round(zscore, 2)
| table _time user src_ip src_country hour typical_hour stdev_hour zscore
| sort - hour_zscore
```

**What it does**

1. Converts each event timestamp into a decimal hour (hour plus minutes/60).
2. Calculates each user's average login hour and standard deviation across the events in the selected search window.
3. Calculates the absolute z-score for the observed login hour relative to that user's average.
4. Keeps rows where the z-score is greater than 3, then displays the time, user, source IP, country, observed hour, baseline, standard deviation, and score.

**Screenshot observations:** two rows are shown. `njackson` has `src_ip` `73.162.88.41`, country `US`, observed hour `3.28`, typical hour `13.50`, standard deviation `1.86`, and z-score `5.49`. `jsmith` has `src_ip` `72.14.201.12`, country `US`, observed hour `18.67`, typical hour `13.48`, standard deviation `1.73`, and z-score `3.01`. The UI shows these events at `2026-03-20 03:17:00` and `2026-03-11 18:40:00` respectively. These are anomaly candidates, not proof of account compromise.

**Important query issue:** the last line sorts by `hour_zscore`, but the query creates a field named `zscore`. Unless `hour_zscore` already exists in the data, use `| sort - zscore` to sort by the calculated score. The screenshot shows the result rows and scores, but does not prove that the final sort field was valid or affected the displayed order.

**Hunting and validation caveats:**

- `stdev_hour` can be zero or null for users with too few or identical-hour events; division can then produce null/infinite-like behavior depending on the data and SPL evaluation. Filter or handle these cases explicitly.
- Clock time is circular: 23:55 and 00:05 are only ten minutes apart but appear far apart under simple subtraction. A circular time-of-day baseline is more accurate for mature detection logic.
- The average and standard deviation are calculated over the current search window, so the baseline can change when the time range changes. Prefer a defined historical baseline and minimum event count for production use.
- Verify the meaning and timezone of `_time`, data coverage, VPN event semantics, and field extraction for `user`, `src_ip`, and `src_country`.
- Investigate unusual login time with other signals (new device, impossible travel, MFA outcomes, failed logins, and user confirmation) before escalating.

