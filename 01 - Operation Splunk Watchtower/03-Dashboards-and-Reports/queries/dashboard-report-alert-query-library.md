# Dashboard, Report, and Alert SPL Query Library

These are the queries supplied for this module. Validate index names, field names, field types, time ranges, and syntax against the actual lab before using them operationally.

## 1. VPN logins by username

```spl
index = vpn_server | stats count by Username | sort - count
```

**Purpose:** Count events per username and sort highest count first.

## 2. Requests to restricted content from outside private address ranges

```spl
index = web_logs URI = /restricted.html NOT Source_IP IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
```

**Purpose:** Find requests to `/restricted.html` whose source is intended to be outside the listed private IPv4 ranges. **Validation note:** Confirm how `Source_IP` is populated and whether CIDR matching in this expression is supported as written; a plain `IN` comparison may not perform network-range matching in every SPL context.

## 3. Hourly 404 counts for `/payments.html`

```spl
index = web_logs URI = /payments.html status_code = 404
| bin _time span=1h
| stats count AS hits BY _time
| eventstats avg(hits) AS avg_hits
| eval avg_hits = round(avg_hits, 1)
```

**Purpose:** Aggregate matching 404 responses into hourly buckets and calculate the average hourly count across the returned buckets.

## 4. Hourly 404 threshold search

```spl
index = web_logs URI = /payments.html status_code = 404
| bin _time span=1h
| stats count AS hits BY _time
| where hits > 11
| eval alert = "HIGH 404s: ".hits." in 1h (normal: ~7.6/hr)"
```

**Purpose:** Return hourly buckets with more than 11 matching 404 responses and label them. This query creates a result field named `alert`; it does not by itself configure a saved Splunk alert or send a notification. The stated normal rate is supplied context and should be validated against a suitable baseline.

## 5. Response-code distribution for restricted content

```spl
index = web_logs URI = /restricted.html
| stats count by status_code
| eventstats sum(count) as total
| eval percent = round(count * 100.0 / total, 2)
| sort - count
```

**Purpose:** Count response codes, calculate each code's percentage of the returned total, and sort by count descending.

## Operational notes

- Set a deliberate time range; avoid broad all-time searches in production unless justified.
- Confirm the actual index and exact field spelling/case in the target dataset.
- A query returning rows is not proof that an alert is saved, scheduled, or delivering email. Verify alert configuration and trigger history separately.
- The screenshots are evidence of the captured UI states; the documentation does not claim a live dashboard, scheduled report, or alert was deployed in the current lab.
