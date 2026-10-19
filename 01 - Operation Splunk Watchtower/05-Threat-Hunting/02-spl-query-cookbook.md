# SPL Query Cookbook — Threat Hunting

Confirm the actual index, time range, and field names in the lab.

## URI frequency
```spl
index="main"
| stats count by URI
| sort - count
```

## Username frequency
```spl
index="main"
| stats count by Username
| sort - count
```
Activity count is a baseline, not a risk score.

## Source-IP frequency
```spl
index="main"
| stats count by SourceIP
| sort - count
```

## Sensitive-document search
```spl
index="main" "secret-document.pdf"
```
This searches event text for the filename. Inspect the raw event; it does not guarantee the `URI` field was extracted correctly.

## Username pivot
```spl
index="main" Username="REPLACE_WITH_USER"
| sort - _time
```

## Source-IP pivot
```spl
index="main" SourceIP="REPLACE_WITH_IP"
| stats count by Username URI Country
| sort - count
```

## Evidence table
```spl
index="main" "secret-document.pdf"
| table _time Username Department SourceIP URI Country host source sourcetype
| sort - _time
```
