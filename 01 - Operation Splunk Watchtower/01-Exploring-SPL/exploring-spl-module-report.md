# Module Report --- Exploring SPL

## Status

Evidence received; documentation draft created. This module is part of
an ongoing project and is not yet the final project report.

## Learning objectives

-   Navigate Search & Reporting.
-   Use the time range picker and search history.
-   Explore hosts, sources, sourcetypes, and field values.
-   Filter events using field operators and Boolean conditions.
-   Select, rename, sort, and deduplicate output fields.
-   Explore regex, top values, joins, statistics, and timecharts.

## Evidence-derived observations

  --------------------------------------------------------------------------------------------------
  Observation                 Evidence shown          Interpretation
  --------------------------- ----------------------- ----------------------------------------------
  Search for                  Screenshot reports 53   A source-IP filter returned 53 events in the
  `SourceIp="172.90.12.11"`   events                  displayed search context.

  Search for `EventID=4624`   Screenshot reports 26   26 matching events were shown. Validate event
                              events                  source and time range.

  Destination `172.18.39.6`,  Screenshot reports 4    Four matching events were shown. This is not
  port `135`                  events                  proof of an attack.

  `TargetObject` ending in    Search uses `regex` and User notes identify
  `Manager`                   `top`                   `HKLM\\SOFTWARE\\Microsoft\\SecurityManager`
                                                      as the highest-count value in the displayed
                                                      result.

  Process command line        Process table           Potentially suspicious account-management
  includes                    screenshot              behavior; requires corroboration and cannot
  `net user /add ...`                                 alone prove successful account creation.
  --------------------------------------------------------------------------------------------------

| Image risk-score lookup | Screenshot 21 | Query enriches Windows process-image events from `image_riskscore` and aggregates counts by image and risk score. Lookup configuration and the resulting score table were not provided, so coverage and top-risk image are unverified. |
| VPN login-hour z-score | Screenshot 22 | Two candidate outliers are displayed with z-scores 5.49 and 3.01. Treat as anomaly candidates, not confirmed compromise. The SPL's final sort references `hour_zscore`, while the calculated field is `zscore`. |

## Analyst notes

-   Screenshots include event timestamps around 2022-04-15, while the
    search UI also displays a later job-time context. Preserve the event
    timestamp and search execution context separately.
-   Several field names differ in capitalization or naming (`SourceIp`,
    `DestinationIp`, `IpAddress`, `AccountName`, `User`). Validate each
    field in the target index before reusing a query.
-   A query returning a count is not the same as a confirmed finding.
    Record query, time range, raw evidence, and interpretation
    separately.

## Skills demonstrated by this evidence

SPL filtering, field discovery, event table formatting, result ordering,
aggregation, regular-expression filtering, visualization, and basic
event correlation.

## Remaining work

-   Capture environment/index/sourcetype details.
-   Validate each query live and attach current result screenshots.
-   Add dashboard, alert, configuration, and data-ingestion evidence in
    later modules.
-   Build an end-to-end threat-hunting case only after corroborating
    telemetry is available.
