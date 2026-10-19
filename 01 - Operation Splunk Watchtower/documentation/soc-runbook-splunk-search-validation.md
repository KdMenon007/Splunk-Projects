# SOC Runbook --- Exploring and Validating Splunk Searches

## 1. Establish scope

-   Confirm authorized lab and index.
-   Select a suitable time range; note it in the evidence.
-   Record host, source, sourcetype, and event count.

## 2. Explore data

-   Use Data Summary to review hosts, sources, and sourcetypes.
-   Review Selected Fields and Interesting Fields.
-   Inspect sample raw events before assuming a field's meaning.

## 3. Build a query safely

-   Start with `index=windowslogs` only if that index exists in the lab.
-   Add one filter at a time.
-   Confirm each field name and result count.
-   Use `table` to display investigation fields.
-   Use `stats` or `timechart` only after understanding the underlying
    event population.

## 4. Correlate events

-   Confirm correlation keys are semantically equivalent.
-   Record unmatched events and possible join limitations.
-   For high-volume datasets, assess the cost of `join` and consider
    other aggregation/correlation patterns.

## 5. Save evidence

-   Export or screenshot relevant results.
-   Name files descriptively, using module and sequence.
-   Keep original evidence unchanged; annotate copies separately.
-   Record query, time range, result count, and interpretation in the
    evidence register.

## 6. Quality checks

-   Does the query run without errors?
-   Are results consistent with the intended hypothesis?
-   Are field names and timestamp interpretations correct?
-   Are conclusions limited to what the evidence supports?
-   Is sensitive data removed before public sharing?
