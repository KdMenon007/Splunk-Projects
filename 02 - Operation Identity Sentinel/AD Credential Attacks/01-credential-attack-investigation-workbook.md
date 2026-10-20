# Credential Attack Investigation Workbook

## Scenario 1 — Kerberoasting
**Index:** `task2` · **Event:** `4769` (Kerberos service ticket requested)

### Step 1 — Find RC4 service-ticket requests
```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```
Look for one requester obtaining tickets for multiple service accounts in a short interval. RC4 is a lead, not a verdict.

### Step 2 — Count targeted services by account and source
```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
| sort - targeted_services
```
Check the requesting account, source, distinct service count, and privilege level of targeted accounts using trusted AD inventory.

### Step 3 — Detect a burst regardless of encryption type
```spl
index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5
| sort - unique_spns
```
The threshold is a lab starting point; tune it to the environment's baseline.

## Scenario 2 — AS-REP Roasting
**Index:** `task3` · **Event:** `4768` (Kerberos TGT requested)

### Step 1 — Establish baseline
```spl
index=task3 EventCode=4768
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
| sort _time
```

### Step 2 — Find requests with pre-authentication type zero
```spl
index=task3 EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
| sort _time
```
Confirm account configuration, source address, and surrounding events before assigning intent.

### Step 3 — Check related logon/service-ticket activity
Replace `ACCOUNT_NAME` with the identified account and use a time range covering the event.
```spl
index=task3 (EventCode=4624 OR EventCode=4769)
| search Account_Name="ACCOUNT_NAME"
| table _time, EventCode, Account_Name, Client_Address
| sort _time
```
No results can support the offline-cracking hypothesis but are not conclusive. Check indexes, field mappings, and the selected time range.

## Scenario 3 — LSASS dumping
**Index:** `task4` · **Event:** Sysmon `10` (ProcessAccess)

### Step 1 — Baseline LSASS access
```spl
index=task4 EventCode=10 TargetImage="*\lsass.exe"
| stats count by SourceImage, GrantedAccess
| sort - count
```

### Step 2 — Inspect suspicious process access
Replace the process filter with the process found in your own baseline.
```spl
index=task4 EventCode=10 TargetImage="*\lsass.exe" SourceImage="*\procdump64.exe"
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
| sort _time
```

### Step 3 — Triage
- Check full executable path, signer/hash, parent process, and whether the tool is approved.
- Identify the source account and review its recent logons and privilege context.
- `0x1FFFFF` represents broad access; `0x1010` includes limited query access plus memory read. Interpret in context.
- `dbgcore.dll`/`dbghelp.dll` can be consistent with MiniDump-style access; `UNKNOWN` call-trace offsets warrant investigation but do not prove injection.
- Correlate with process creation, logons, EDR, host role, and subsequent credential use.

**Visibility caveat:** Sysmon Event 10 only helps if ProcessAccess rules capture LSASS access. Confirm telemetry coverage before relying on missing events.

## Investigation checklist
- [ ] Confirm index, sourcetype, field extraction, and time range.
- [ ] Record exact SPL and result count.
- [ ] Capture account, source, target, and timestamps.
- [ ] Correlate Windows Security, Sysmon, EDR, and AD audit telemetry.
- [ ] Document benign explanations, confidence, and evidence gaps.
