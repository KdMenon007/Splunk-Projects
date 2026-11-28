# Build Status — Operation Cloud Mailwatch

This document tracks the incremental build, validation status, and screenshot evidence collection for **Operation Cloud Mailwatch**.

---

## Current Status Summary

| Module / Component | SPL Queries | Investigation Findings | Mermaid Diagrams | Screenshot Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **01 — Password-Based Attacks** | Completed & Saved (`.spl` + `.md`) | Completed | Completed | **4 Screenshots Verified** (`task-2`) |
| **02 — Conditional Access & Identity Protection** | Completed & Saved (`.spl` + `.md`) | Completed | Completed | **2 Screenshots Verified** (`task-3`) |
| **03 — MFA Bypass Techniques** | Completed & Saved (`.spl` + `.md`) | Completed | Completed | **3 Screenshots Verified** (`task-4`) |
| **04 — Privilege Escalation & Persistence** | Completed & Saved (`.spl` + `.md`) | Completed | Completed | **2 Screenshots Verified** (`task-5`; MFA registration optional) |
| **05 — OAuth Application Abuse** | Completed & Saved (`.spl` + `.md`) | Reference Logic Documented | Completed | N/A (Conceptual / Audit Schema Module) |
| **SOC Investigation Playbooks** | N/A | Completed | Completed | N/A |

---

## Phased Checklist

### Phase 1 — Starter Workspace
- [x] Create standardized project directory structure
- [x] Generate initial `README.md`, `BUILD-STATUS.md`, and workspace READMEs

### Phase 2 — Technical Development & Evidence Integration
- [x] Archive original investigation notes verbatim in `docs/01-entra-id-monitoring-source.md`
- [x] Refactor Q&A notes into portfolio-grade SPL detection modules (`detections/splunk/01`–`05`)
- [x] Export consolidated runnable query pack (`detections/splunk/all-detections.spl`)
- [x] Create Mermaid architecture, kill-chain, timeline, and SOC triage flowcharts (`docs/architecture-and-workflows.md`)
- [x] Integrate and catalog **11 verified Splunk validation screenshots** across Modules 01–04 in `evidence/screenshots/`
- [x] Author step-by-step SOC investigation playbooks (`investigation-playbooks/README.md`)

### Phase 3 — GitHub Publication
- [x] Remove Q&A formatting across all portfolio markdown files
- [x] Verify all screenshot links and relative paths
- [x] Package and validate GitHub-ready ZIP archive (`v3`)
