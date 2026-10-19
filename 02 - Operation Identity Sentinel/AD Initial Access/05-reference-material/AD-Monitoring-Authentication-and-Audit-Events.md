# Active Directory Monitoring --- Authentication and Audit Events

**Project:** Operation Identity Sentinel\
**Organization:** CatchMe Security Operations\
**Topics:** AD authentication, credential-access indicators, account
lifecycle, group membership, directory changes, Splunk SPL, and audit
policy.

> These notes organize the supplied training material. Indexes and field
> names are examples and must be validated against actual Splunk data.
> Suspicious indicators are investigation leads, not proof of
> compromise.

## 1. Protocol overview

  -----------------------------------------------------------------------
  Protocol / service      Ports                   Purpose and normal
                                                  usage
  ----------------------- ----------------------- -----------------------
  Kerberos                88                      Domain authentication,
                                                  logins, service access,
                                                  ticket requests

  LDAP / LDAPS / Global   389, 636, 3268, 3269    Directory queries and
  Catalog                                         modifications

  SMB / legacy NetBIOS    445; 139 for legacy     File shares and remote
  session service         sessions                administration

  RDP                     3389                    Interactive remote
                                                  desktop

  NetBIOS name service /  137, 138, 5355          Legacy or fallback name
  LLMNR                                           resolution
  -----------------------------------------------------------------------

## 2. Domain accounts vs. local accounts

-   **Domain users** authenticate against a Domain Controller (DC);
    domain credential data is stored in the AD database (`NTDS.dit`). DC
    and target-host events can both be relevant.
-   **Local users** authenticate against the local Security Account
    Manager (SAM) database. Related events may appear only on the local
    machine.

  User type     Credential store           Where to investigate
  ------------- -------------------------- -----------------------------
  Domain user   `NTDS.dit` on a DC         DC and relevant target host
  Local user    SAM on the local machine   Local machine

For cross-system investigations, correlate DC and endpoint telemetry
rather than assuming one source contains the complete picture.

## 3. Kerberos authentication

![Kerberos authentication flow](assets/kerberos-authentication-flow.png)

Kerberos is ticket-based authentication. The user requests a Ticket
Granting Ticket (TGT), then requests a service ticket (TGS) for a
resource, and presents that ticket to the target server.

  Activity                                Event ID Location described in the notes
  ------------------------------------- ---------- ---------------------------------
  TGT request                                 4768 Domain Controller
  TGS request                                 4769 Domain Controller
  Successful logon / session                  4624 Target server
  Kerberos pre-authentication failure         4771 Domain Controller

Event 4771 can occur when users mistype passwords; it is not
automatically malicious.

### Ticket encryption types

  -----------------------------------------------------------------------
  Value                   Algorithm               Context
  ----------------------- ----------------------- -----------------------
  `0x11`                  AES-128                 AES-128 encryption

  `0x12`                  AES-256                 Common with modern
                                                  systems

  `0x17`                  RC4-HMAC                May occur with legacy
                                                  systems, older
                                                  applications, or trust
                                                  scenarios
  -----------------------------------------------------------------------

RC4 usage alone does not prove Kerberoasting. Examine the account,
target services, request volume, timing, and baseline.

**Splunk --- TGT requests**

``` spl
index=* EventCode=4768
| table _time, Account_Name, Client_Address, Ticket_Encryption_Type
```

## 4. NTLM authentication

![NTLM authentication flow](assets/ntlm-authentication-flow.png)

NTLM may be used when Kerberos is unavailable, such as when a resource
is accessed by IP address or a legacy application requires NTLM.

  Activity                          Event ID Location described in the notes
  ------------------------------- ---------- ---------------------------------
  DC validates NTLM credentials         4776 Domain Controller
  Successful logon / session            4624 Target server

**Splunk --- NTLM validation on the DC**

``` spl
index=* EventCode=4776
| table _time, Logon_Account, Source_Workstation
```

**Splunk --- NTLM logon on a target**

``` spl
index=* EventCode=4624 Account_Name=michelle.smith Authentication_Package=NTLM
| table _time, host, user, Workstation_Name, Source_Network_Address, Authentication_Package
```

High volumes of Event 4776 may reflect legacy applications,
misconfiguration, or access by IP address. Investigate account, source
workstation, timing, and baseline.

## 5. Account lifecycle events

    Event ID Activity
  ---------- --------------------------
        4720 Account created
        4722 Account enabled
        4724 Password reset attempted
        4725 Account disabled
        4740 Account locked out

**Splunk --- account creation**

``` spl
index=* EventCode=4720
| table _time, SAM_Account_Name, Subject_Account_Name
```

Review who created the account, whether the name is expected, and
whether the activity aligns with approved onboarding or change
processes. Validate field names against actual event data.

## 6. Security group membership

    Event ID Activity
  ---------- --------------------------------------------
        4728 Member added to a global security group
        4732 Member added to a local security group
        4756 Member added to a universal security group

Monitor privileged groups such as Domain Admins, Enterprise Admins, and
local Administrators.

``` spl
index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time, Member_Account_Name, Group_Name, Subject_Account_Name
```

Investigate who was added, which group changed, who performed the
action, and whether it was authorized.

## 7. Directory service changes --- Event 5136

Event 5136 records attribute-level modifications to AD objects.
Attributes of interest in the supplied notes include
`userAccountControl`, `servicePrincipalName`, `scriptPath`, `member`,
`displayName`, `description`, and `title`.

**Splunk --- GPO-related directory-object changes**

``` spl
index=* EventCode=5136 Class="groupPolicyContainer"
| table _time, Subject_Account_Name, DN, LDAP_Display_Name, Value
| sort - _time
```

This may return no results if no relevant modifications occurred in the
selected time window. Event 5136 can show GPO metadata changes, but not
necessarily the actual policy settings stored in `SYSVOL`; separate
monitoring may be required for those files.

## 8. Logon events and logon types

    Event ID Meaning
  ---------- ------------------
        4624 Successful logon
        4625 Failed logon

    Logon type Meaning             Example
  ------------ ------------------- -----------------------------
             2 Interactive         Local console
             3 Network             File share or network logon
             4 Batch               Scheduled task
             5 Service             Service account
             7 Unlock              Unlock an existing session
            10 RemoteInteractive   Remote Desktop session

**Splunk --- successful logons by type**

``` spl
index=* EventCode=4624
| stats count by Logon_Type
| sort -count
```

Type 3 may dominate in environments with substantial network access, but
compare results with each system's role and baseline.

## 9. Baselines, computer accounts, and stack counting

The supplied notes give rough illustrative daily volumes for a 500-user
environment: Event 4769, 50,000--100,000+; Event 4768, 5,000--10,000+;
Event 4624, highly dependent on server role. These are not universal
baselines.

Computer accounts commonly end in `$` and can generate substantial
background traffic. Filtering them can help focus on human users, but do
not exclude them blindly: unusual machine-account activity can also
matter.

**Splunk --- compare account types**

``` spl
index=* EventCode IN (4624, 4768, 4769)
| eval AccountType=if(like(Account_Name, "%$%"), "Computer Account", "User Account")
| stats count by AccountType, EventCode
| sort AccountType, -count
```

**Stack counting --- service-ticket requests by account**

``` spl
index=* EventCode=4769 NOT Account_Name="*$*"
| stats count by Account_Name
| sort -count
```

Stack counting can also be applied to `Client_Address`, `Service_Name`,
and `Ticket_Encryption_Type`. Rare values are leads to investigate, not
proof of malicious activity.

### Example service-name patterns

  Service name             Example meaning
  ------------------------ ----------------------------------
  `krbtgt`                 Kerberos ticket-granting service
  `cifs/THM-SHR-SRV`       File-share service
  `ldap/THM-DC`            Directory queries
  `http/THM-WEB-SRV`       Web service
  `MSSQLSvc/THM-SQL-SRV`   SQL Server service
  `HOST/THM-IT-DESK`       Host service

### Example time-based baselines

  Activity          Example expected time
  ----------------- ---------------------------------
  User logins       Business hours, e.g. 8 AM--6 PM
  Backup accounts   Overnight, e.g. midnight--4 AM
  Batch jobs        Configured schedule
  Admin accounts    Approved maintenance windows

These are examples from the supplied notes. Establish baselines from the
actual environment.

## 10. Advanced audit policy

The supplied notes recommend reviewing **Computer Configuration →
Policies → Windows Settings → Security Settings → Advanced Audit Policy
Configuration → Audit Policies**.

  -----------------------------------------------------------------------
  Category          Subcategory       Setting in the    Events of
                                      notes             interest
  ----------------- ----------------- ----------------- -----------------
  Account Logon     Credential        Success, Failure  4776
                    Validation                          

  Account Logon     Kerberos          Success, Failure  4768, 4771
                    Authentication                      
                    Service                             

  Account Logon     Kerberos Service  Success, Failure  4769
                    Ticket Operations                   

  Account           User Account      Success, Failure  4720, 4722, 4724,
  Management        Management                          4725

  Account           Security Group    Success, Failure  4728, 4732, 4756
  Management        Management                          

  DS Access         Directory Service Success, Failure  5136
                    Changes                             

  Logon/Logoff      Logon             Success, Failure  4624, 4625

  Object Access     File Share        Success           5140
  -----------------------------------------------------------------------

Verify policy on an authorized Windows system:

``` powershell
# View all audit policy settings
auditpol /get /category:*
```

``` powershell
# View a specific subcategory
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

Missing events may indicate disabled auditing, collection gaps, a
mismatched time range, or field-extraction issues.

## 11. Quick reference

     Event ID Meaning
  ----------- ------------------------------------------
         4624 Successful logon
         4625 Failed logon
         4662 Directory Service Access
         4720 Account created
         4722 Account enabled
         4724 Password reset attempted
         4725 Account disabled
         4728 Member added to global security group
         4732 Member added to local security group
         4740 Account locked out
         4756 Member added to universal security group
         4768 Kerberos TGT request
         4769 Kerberos service-ticket request
         4771 Kerberos pre-authentication failure
         4776 NTLM credential validation
         5136 Directory object modified
     Sysmon 1 Process creation
    Sysmon 10 Process access
    Sysmon 11 File creation

## 12. SOC triage checklist

-   **Who?** Account, subject user, or source process.
-   **What?** Service, process, object, or action.
-   **Where?** Source IP, workstation, host, or DC.
-   **When?** Timestamp and surrounding timeline.
-   **How?** Encryption type, access mask, command line, or changed
    attribute.
-   **How often?** Event volume and distinct targets.
-   **Is it normal?** Compare with known account, host, service, and
    time baselines.
-   **Is it privileged?** Determine the account's role and permissions.
-   **Potential impact?** What data or access could be exposed or
    changed?
-   **Evidence?** Correlate related events and record uncertainty.

## 13. Validation checklist

-   [ ] Confirm the index and sourcetype.
-   [ ] Confirm the events exist in the selected time range.
-   [ ] Verify field names and values against actual events.
-   [ ] Check Windows auditing and Sysmon collection where applicable.
-   [ ] Run searches and inspect representative results.
-   [ ] Consider expected administrative behavior and false positives.
-   [ ] Capture screenshots of actual query results.
-   [ ] Document findings, limitations, and follow-up steps.

**Status:** Source notes and example searches documented. Actual query
results, event availability, and end-to-end detection behavior still
require validation in the target lab.
