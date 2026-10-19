# Project Status and Continuation Notes

**Project:** Operation Splunk Watchtower  
**Organization:** CatchMe  
**Current stage:** Exploring SPL, initial SOC lab setup, and Dashboards and Reports  
**Project status:** In progress — do not mark complete.

## Evidence received

### Module 01 — Exploring SPL
- Source notes and query library.
- 22 screenshots covering search interface, fields, filters, event IDs, result formatting, correlation, visualizations, image-risk lookup, and VPN login-hour anomaly hunting.
- Query observations and validation caveats are documented in the module report and query library.

### Module 02 — Setting Up a SOC Lab
- Supplied `Setting up a SOC Lab(1).md` preserved as `02-Setting-Up-SOC-Lab/setting-up-soc-lab-source-notes.md`.
- Added a structured report covering Linux Splunk Enterprise installation, CLI validation, Universal Forwarder setup, receiving port `9997`, `linux_host` index, and a syslog test marker.
- Added 18 selected architecture and Linux setup screenshots.
- Documented Windows Enterprise, Universal Forwarder, Windows Event Log, and IIS/Coffely log configuration from the supplied notes.
- Windows-specific screenshots and end-to-end Windows ingestion validation are not present in this evidence batch; keep that portion documented but not evidence-verified.

## Observed values and caveats
- Screenshot-based event counts and query results are specific to the captured session and may vary by dataset/time range.
- The image-risk lookup and VPN login-hour z-score queries need validation before operational use.
- The supplied SOC lab notes record a Universal Forwarder management-port conflict on `8089`, changed to `8090` in the same-host lab.
- A configured forwarding target is not proof of successful ingestion; confirm events in the intended index.

## Next collection targets
1. Capture Windows Universal Forwarder status/configuration and Windows Event Log search results.
2. Verify `index=linux_host`, `index=windows_eventlogs`, and `index=coffely_weblogs` against the actual lab.
3. Capture and verify saved dashboard/report/alert states and any alert delivery.
4. Gather data manipulation/parsing evidence.
5. Validate and sanitize before GitHub publication.

## Continuity rules
- Preserve original notes and screenshots.
- Name derived files descriptively.
- Never invent results, alerts, incident impact, or remediation actions.
- Update this document, the file inventory, and evidence register as the project grows.


## Threat Hunting module (added 2026-10-19)
- Workbook and SPL query cookbook added from supplied searches/screenshots.
- Screenshot evidence included unchanged.
- Validation still required in the live lab: index, time range, sourcetype, extracted field names, and event boundaries. No incident conclusion is asserted by this package.
