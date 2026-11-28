# Splunk Detections Workspace

This directory contains structured, portfolio-ready Splunk Processing Language (SPL) detection rules, a consolidated `.spl` query pack, and threat-hunting documentation for **Microsoft Entra ID**.

---

## Detection Catalog

| Module File | Threat Domain | Sourcetype | Validation Status |
| :--- | :--- | :--- | :--- |
| [`all-detections.spl`](all-detections.spl) | Consolidated Runnable SPL Query Pack (Modules 01–05) | All Entra ID Sourcetypes | **Ready to Run** |
| [`01-password-based-attacks.md`](01-password-based-attacks.md) | Password Spraying, Throttling Brute Force & Compromise Pivot | `azure:aad:signin` | **Validated (4 Screenshots Attached)** |
| [`02-conditional-access-identity-protection.md`](02-conditional-access-identity-protection.md) | Risky Users & Conditional Access Policy Blocks | `azure:aad:identity_protection:risky_user`, `azure:aad:signin` | **Validated (2 Screenshots Attached)** |
| [`03-mfa-bypass-techniques.md`](03-mfa-bypass-techniques.md) | MFA Fatigue (Prompt Bombing) & Geographic Baseline Deviation | `azure:aad:signin` | **Validated (3 Screenshots Attached)** |
| [`04-privilege-escalation-persistence.md`](04-privilege-escalation-persistence.md) | Rogue User Creation, Global Admin Assignment & MFA Registration | `azure:aad:audit` | **Validated (2 Screenshots Attached)** |
| [`05-oauth-application-abuse.md`](05-oauth-application-abuse.md) | Malicious OAuth Application Consent & `Mail.Read.All` Exposure | `azure:aad:audit` | Detection Logic Documented |
