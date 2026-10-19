# Splunk: Dashboards and Reports — Module Report

**Project:** Operation Splunk Watchtower  
**Organization:** CatchMe  
**Module:** `03-Dashboards-and-Reports`  
**Status:** In progress — source notes, query library, and screenshots organized; live configuration and end-to-end alert delivery remain to be verified.

## Objective

Turn SPL searches into reusable reports, dashboard panels, visual summaries, and threshold-oriented alert searches. The material covers VPN login counts, web requests to restricted content, hourly 404 counts for `/payments.html`, and response-code distribution.

## Workflows documented

1. **Search & Reporting:** Run a query and inspect event, field, and statistics results.
2. **Reports:** Save a search as a report, choose a title/description and table content, view it, and optionally configure a schedule.
3. **Dashboards:** Create a dashboard, choose Classic Dashboards or Dashboard Studio, add a panel from a report or new search, and choose an appropriate visualization.
4. **Alerts:** Configure a saved alert's trigger condition, schedule, throttling, and action where supported. A threshold SPL query alone is not a configured alert.

## Query scenarios

- VPN activity summary: count events by `Username`.
- Restricted URI investigation: filter requests to `/restricted.html` and examine source address context.
- HTTP error monitoring: bucket `/payments.html` 404 events into one-hour intervals, calculate average hourly volume, and identify buckets over the supplied threshold of 11.
- Response-code distribution: count and calculate percentage by `status_code` for `/restricted.html`.

The exact SPL supplied is preserved in `queries/dashboard-report-alert-query-library.md`.

## Evidence included

- Original supplied Markdown source notes.
- 16 screenshots covering search/results, report creation and viewing, schedule settings, field analysis, alert configuration/results, dashboard creation, and panel configuration.
- A query library with purpose and validation notes.

## Validation and limitations

- Screenshots represent captured UI states; their counts and results are dataset- and time-range-dependent.
- The provided `Source_IP NOT IN (...)` expression should be validated for actual CIDR/network-range semantics before relying on it to classify public versus private addresses.
- The 404 query's `alert` field is only a search result label; save/configure a Splunk alert separately to schedule evaluation or trigger an action.
- Verify the index names (`vpn_server`, `web_logs`) and fields (`Username`, `URI`, `Source_IP`, `status_code`) in the target lab.
- No claim is made that the shown reports, dashboards, schedules, or email alerts are currently deployed or have delivered notifications in the user's environment.

## Suggested completion evidence

1. Capture a successful run of each query with the selected time range visible.
2. Capture the saved report details and schedule state.
3. Capture the dashboard with saved panels and permissions.
4. Capture saved alert trigger settings and trigger history; if email is configured, validate delivery with a controlled test.
5. Update the evidence register only for states actually observed.
