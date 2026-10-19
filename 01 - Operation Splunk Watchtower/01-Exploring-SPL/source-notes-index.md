# Exploring SPL — Source Notes

This reference summarizes the user-provided notes and screenshots for Operation Splunk Watchtower.

## Search & Reporting interface
- Search Head: interface for running SPL searches, visualizing results, and pivoting through events.
- Time range picker: all time, last 60 minutes, and custom ranges.
- Search history: review and rerun prior queries.
- Data Summary: hosts, sources, and sourcetypes.
- Field sidebar: selected fields, interesting fields, field value counts, and field-type indicators.

## SPL concepts covered in the source notes
- Comparison operators: `=`, `!=`, `<`, `<=`, `>`, `>=`.
- Boolean operators: `AND`, `OR`, `NOT`.
- Wildcard matching with `*`.
- Commands: `fields`, `search`, `dedup`, `rename`, `table`, `head`, `tail`, `sort`, `reverse`.
- Additional queries shown in screenshots: `regex`, `top`, `join`, `highlight`, `stats`, and `timechart`.

The original uploaded file is included in this package when available. This file is a compact index, not a replacement for the original notes.


## Additional SPL techniques evidenced by screenshots 21–22
- Lookup enrichment: `lookup image_riskscore Image OUTPUT RiskScore`, followed by aggregation and sorting.
- Behavioral anomaly scoring: `eval`, `eventstats`, `avg`, `stdev`, `abs`, and a z-score threshold applied to VPN login hour.
- Validation issue noted: the VPN query calculates `zscore` but sorts by `hour_zscore`; confirm or correct the field name before relying on sort order.
