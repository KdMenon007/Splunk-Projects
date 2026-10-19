
I’ll separate **queries directly based on the material you provided** from **additional hunting queries** so you know what is source-derived versus practical SOC additions.

> **Assumption:** CloudTrail events are normalized into Splunk with fields such as `eventName`, `eventSource`, `userIdentity.*`, `sourceIPAddress`, `userAgent`, `readOnly`, `awsRegion`, `requestParameters.*`, etc. Field extraction varies by Splunk AWS add-on, so you may need to adjust field names.

---

# ☁️ AWS CLOUD SECURITY — SPLUNK CHEAT SHEET

## 0. First: Know Your Main Log Sources

Think of AWS monitoring as several telemetry layers:

```text
                    AWS CLOUD
                       │
       ┌───────────────┼────────────────┐
       │               │                │
   CONTROL PLANE    NETWORK          WORKLOAD
       │               │                │
   CloudTrail      VPC Flow Logs     Falco / EDR
       │               │                │
       ├───────────────┤                │
       │                                │
   GuardDuty                         Containers
       │                                │
       └───────────────┬────────────────┘
                       ↓
                     SIEM
                       ↓
                    SPLUNK
```

### Main sources

|Source|What you see|
|---|---|
|CloudTrail|AWS API/control-plane activity|
|GuardDuty|AWS threat findings|
|VPC Flow Logs|Network flows|
|CloudFront|Web requests|
|S3 Data Events|Object-level access|
|CloudWatch|Service/application logs|
|Falco|Runtime/container events|
|EDR|Endpoint behavior|
|DNS logs|DNS activity|

---

# 1. AWS BASELINE

Start by checking whether AWS logs are actually arriving.

```spl
index=aws
| stats count
```

Events by source:

```spl
index=aws
| stats count by eventSource
| sort -count
```

Events by event name:

```spl
index=aws
| stats count by eventName
| sort -count
```

Events over time:

```spl
index=aws
| timechart count
```

Events by AWS account:

```spl
index=aws
| stats count by recipientAccountId
| sort -count
```

Events by region:

```spl
index=aws
| stats count by awsRegion
| sort -count
```

---

# 2. CONTROL-PLANE MONITORING

CloudTrail is your primary control-plane source.

## All write operations

The material emphasizes `readOnly=false`.

```spl
index=aws readOnly=false
| stats count by eventSource eventName
| sort -count
```

This is an excellent starting point.

---

# 3. High-Risk AWS API Calls

```spl
index=aws readOnly=false
| search eventName IN (
    CreateUser,
    CreateAccessKey,
    UpdateAccessKey,
    AttachUserPolicy,
    AttachRolePolicy,
    AttachGroupPolicy,
    PutUserPolicy,
    PutRolePolicy,
    PutGroupPolicy,
    AddUserToGroup,
    CreateRole,
    UpdateAssumeRolePolicy,
    DeleteVirtualMFADevice,
    DeactivateMFADevice
)
| table _time userIdentity.arn eventName sourceIPAddress userAgent awsRegion requestParameters
```

---

# 4. Who Is Making AWS Changes?

```spl
index=aws readOnly=false
| stats count by userIdentity.arn
| sort -count
```

Username:

```spl
index=aws readOnly=false
| stats count by userIdentity.userName
| sort -count
```

Source IP:

```spl
index=aws readOnly=false
| stats count by sourceIPAddress
| sort -count
```

User + IP:

```spl
index=aws readOnly=false
| stats count by userIdentity.userName sourceIPAddress
| sort -count
```

---

# 🔐 IAM MONITORING

# 5. Console Logins

All console logins:

```spl
index=aws eventName=ConsoleLogin
| table _time userIdentity.userName userIdentity.type sourceIPAddress userAgent errorMessage additionalEventData.MFAUsed awsRegion
```

---

# 6. Successful Console Logins

```spl
index=aws eventName=ConsoleLogin
| search responseElements.ConsoleLogin=Success
| table _time userIdentity.userName sourceIPAddress userAgent additionalEventData.MFAUsed
```

If your extraction uses `additionalEventData` differently, adjust the field.

---

# 7. Failed Console Logins

```spl
index=aws eventName=ConsoleLogin
| search errorMessage="Failed authentication"
| stats count by userIdentity.userName sourceIPAddress
| sort -count
```

---

# 8. Brute-Force Detection

```spl
index=aws eventName=ConsoleLogin errorMessage="Failed authentication"
| stats count as failures by sourceIPAddress userIdentity.userName
| where failures >= 10
| sort -failures
```

Better time-based detection:

```spl
index=aws eventName=ConsoleLogin errorMessage="Failed authentication"
| bin _time span=15m
| stats count as failures by _time sourceIPAddress userIdentity.userName
| where failures >= 10
```

---

# 9. Successful Login After Multiple Failures

This is much more interesting than simply detecting failures.

```spl
index=aws eventName=ConsoleLogin
| eval status=if(isnull(errorMessage),"SUCCESS","FAILURE")
| bin _time span=15m
| stats
    count(eval(status="FAILURE")) as failures
    count(eval(status="SUCCESS")) as successes
    by _time sourceIPAddress userIdentity.userName
| where failures >= 5 AND successes > 0
```

This can identify:

```text
Brute force
    ↓
Successful authentication
```

---

# 10. Root User Login

```spl
index=aws eventName=ConsoleLogin
| search userIdentity.type=Root
| table _time sourceIPAddress userAgent additionalEventData.MFAUsed
```

### Why important?

Root should normally be used only for exceptional administrative tasks.

Any unexpected root activity deserves investigation.

---

# 11. Root Activity

```spl
index=aws userIdentity.type=Root
| stats count by eventName sourceIPAddress userAgent
| sort -count
```

---

# 12. Root Access Key Creation

Hunt for:

```spl
index=aws
| search eventName=CreateAccessKey userIdentity.type=Root
| table _time sourceIPAddress userAgent eventName requestParameters
```

This should be treated as highly suspicious.

---

# 13. Service Account Console Login

Service identities generally should not be using interactive console access.

You can create an organization-specific list of service users.

Example:

```spl
index=aws eventName=ConsoleLogin
| search userIdentity.userName IN ("svc-backup","svc-cicd","svc-monitoring")
| table _time userIdentity.userName sourceIPAddress userAgent
```

---

# 14. Login Without MFA

```spl
index=aws eventName=ConsoleLogin
| search additionalEventData.MFAUsed!="Yes"
| table _time userIdentity.userName sourceIPAddress userAgent additionalEventData.MFAUsed
```

---

# 15. Suspicious Login IPs

Start with unusual sources:

```spl
index=aws eventName=ConsoleLogin
| stats count by sourceIPAddress userIdentity.userName
| sort -count
```

Then enrich suspicious IPs with your threat-intelligence workflow.

---

# 16. First-Seen Login IP

A very useful hunting concept:

```spl
index=aws eventName=ConsoleLogin
| stats earliest(_time) as firstSeen latest(_time) as lastSeen count by userIdentity.userName sourceIPAddress
| eval firstSeen=strftime(firstSeen,"%Y-%m-%d %H:%M:%S")
| eval lastSeen=strftime(lastSeen,"%Y-%m-%d %H:%M:%S")
| sort userIdentity.userName firstSeen
```

This helps establish:

> "Has this user ever logged in from this IP before?"

---

# 🔑 ACCESS KEY MONITORING

# 17. Find Access-Key-Based Activity

The material gives:

```spl
index=aws userIdentity.accessKeyId=AKIA*
```

Use:

```spl
index=aws userIdentity.accessKeyId=AKIA*
| table _time userIdentity.userName userIdentity.accessKeyId eventSource eventName sourceIPAddress userAgent
```

---

# 18. Find Programmatic Activity

```spl
index=aws
| search userIdentity.accessKeyId=AKIA*
| stats count by userIdentity.userName userIdentity.accessKeyId userAgent sourceIPAddress
| sort -count
```

---

# 19. Find Access Key Activity From ASIA Temporary Credentials

Temporary STS credentials commonly begin with `ASIA`.

```spl
index=aws userIdentity.accessKeyId=ASIA*
| stats count by userIdentity.arn userIdentity.accessKeyId userAgent sourceIPAddress
| sort -count
```

---

# 20. Detect Access-Key Activity From Unexpected IP

Baseline by user:

```spl
index=aws userIdentity.accessKeyId=AKIA*
| stats count by userIdentity.userName sourceIPAddress
| sort userIdentity.userName -count
```

Then identify deviations from your normal IP ranges.

---

# 21. Access Key Creation

```spl
index=aws eventName=CreateAccessKey
| table _time userIdentity.userName userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 22. Access Key Update

```spl
index=aws eventName=UpdateAccessKey
| table _time userIdentity.userName sourceIPAddress requestParameters
```

---

# 23. Access Key Creation Followed by Suspicious Activity

Conceptual hunting:

```spl
index=aws
| search eventName IN (CreateAccessKey, DeleteBucket, GetObject, PutObject, RunInstances)
| sort _time
| table _time userIdentity.userName eventName sourceIPAddress userAgent requestParameters
```

For production detection, use correlation searches/risk-based alerting rather than a simple sequence query.

---

# 24. IAM Policy Changes

```spl
index=aws eventName IN (
    PutUserPolicy,
    PutRolePolicy,
    PutGroupPolicy
)
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
```

---

# 25. Policy Attachment

```spl
index=aws eventName IN (
    AttachUserPolicy,
    AttachRolePolicy,
    AttachGroupPolicy
)
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
```

---

# 26. AdministratorAccess Assignment

```spl
index=aws
| search eventName IN (
    AttachUserPolicy,
    AttachRolePolicy,
    AttachGroupPolicy
)
| search "AdministratorAccess"
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
```

This is a **high-priority IAM detection**.

---

# 27. User Added to Group

```spl
index=aws eventName=AddUserToGroup
| table _time userIdentity.userName sourceIPAddress requestParameters
```

Hunt specifically for privileged groups:

```spl
index=aws eventName=AddUserToGroup
| search requestParameters.groupName IN ("Administrators","Admins","SecurityAdmins")
| table _time userIdentity.userName sourceIPAddress requestParameters
```

Use your actual group names.

---

# 28. MFA Disabled

```spl
index=aws eventName IN (
    DeleteVirtualMFADevice,
    DeactivateMFADevice
)
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
```

### Very important correlation

```text
MFA disabled
      ↓
New MFA device created
```

could be legitimate account recovery.

But:

```text
MFA disabled
      ↓
No replacement MFA
      ↓
Privileged activity
```

is suspicious.

---

# 29. IAM Role Monitoring

Create role:

```spl
index=aws eventName=CreateRole
| table _time userIdentity.userName sourceIPAddress requestParameters
```

Role policy changes:

```spl
index=aws eventName IN (
    PutRolePolicy,
    AttachRolePolicy
)
| table _time userIdentity.userName sourceIPAddress requestParameters
```

Trust-policy changes:

```spl
index=aws eventName=UpdateAssumeRolePolicy
| table _time userIdentity.userName sourceIPAddress requestParameters
```

---

# 🎭 ROLE ASSUMPTION

# 30. AssumeRole

```spl
index=aws eventName=AssumeRole
| table _time userIdentity.arn userIdentity.userName sourceIPAddress userAgent requestParameters.roleArn requestParameters.roleSessionName
```

---

# 31. Hunt Suspicious Role Assumption

```spl
index=aws eventName=AssumeRole
| stats count by userIdentity.arn requestParameters.roleArn sourceIPAddress userAgent
| sort -count
```

Look for:

```text
New user
+
new role
+
new IP
```

---

# 32. Custom Role Session Names

Look at:

```spl
index=aws eventName=AssumeRole
| table _time userIdentity.arn requestParameters.roleArn requestParameters.roleSessionName sourceIPAddress
```

A strange session name deserves investigation.

---

# 33. Role Chaining

Find role assumptions:

```spl
index=aws eventName=AssumeRole
| sort _time
| table _time userIdentity.arn requestParameters.roleArn requestParameters.roleSessionName sourceIPAddress
```

Conceptually:

```text
User
 ↓
Role A
 ↓
Role B
 ↓
Role C
```

For serious environments, build a correlation/search workflow around the session identifiers and CloudTrail session context.

---

# 34. S3 PUBLIC EXPOSURE

This is one of the most important cloud detections.

# 35. Public Access Block Disabled

```spl
index=aws eventName=PutBucketPublicAccessBlock
| table _time userIdentity.userName sourceIPAddress requestParameters
```

Look specifically for disabling behavior in the extracted request fields.

---

# 36. Bucket Policy Changes

```spl
index=aws eventName=PutBucketPolicy
| table _time userIdentity.userName sourceIPAddress requestParameters
```

---

# 37. Hunt `Principal="*"`

```spl
index=aws eventName=PutBucketPolicy
| search requestParameters="*"
| search "Principal"="*"
| table _time userIdentity.userName sourceIPAddress requestParameters
```

Field extraction differs significantly between AWS add-ons, so searching the raw policy is sometimes necessary.

---

# 38. Public S3 Policy — Better Conceptual Detection

Look for:

```text
Effect = Allow
Principal = *
Action = s3:GetObject
```

Potential Splunk approach:

```spl
index=aws eventName=PutBucketPolicy
| regex _raw="(?i)\"Effect\"\s*:\s*\"Allow\""
| regex _raw="(?i)\"Principal\"\s*:\s*\"\\*\""
| table _time userIdentity.userName sourceIPAddress requestParameters
```

Then manually inspect:

```text
Condition
Action
Resource
Deny statements
```

**Don't automatically classify every `Principal="*"` as malicious.**

---

# 39. S3 Object Access

If S3 Data Events are enabled:

```spl
index=aws eventName IN (GetObject, PutObject, DeleteObject)
| table _time userIdentity.arn eventName sourceIPAddress requestParameters
```

---

# 40. Anonymous S3 Access

```spl
index=aws eventName IN (GetObject, HeadObject)
| search userIdentity.type="Anonymous"
| table _time eventName sourceIPAddress requestParameters
```

Your exact anonymous identity field may vary.

---

# 41. S3 Object Brute Force

A powerful detection:

```spl
index=aws eventName IN (GetObject,HeadObject)
| search errorCode=AccessDenied
| bin _time span=10m
| stats count as denied by _time sourceIPAddress requestParameters.bucketName
| where denied >= 20
| sort -denied
```

Interpretation:

```text
Many failed object requests
        ↓
Same IP
        ↓
Same bucket
        ↓
Possible filename enumeration
```

---

# 42. S3 Mass Download

```spl
index=aws eventName=GetObject
| bin _time span=10m
| stats count as downloads by _time userIdentity.arn sourceIPAddress requestParameters.bucketName
| where downloads >= 100
| sort -downloads
```

Tune `100` for your environment.

---

# 43. S3 Mass Delete

```spl
index=aws eventName=DeleteObject
| bin _time span=10m
| stats count as deletes by _time userIdentity.arn sourceIPAddress requestParameters.bucketName
| where deletes >= 50
| sort -deletes
```

---

# 44. S3 Data Exfiltration

Hunt for:

```text
GetObject
+
unusual user
+
new IP
+
high volume
```

```spl
index=aws eventName=GetObject
| stats count by userIdentity.arn sourceIPAddress requestParameters.bucketName
| sort -count
```

Then investigate unusual combinations.

---

# 🌐 EC2 / SECURITY GROUP MONITORING

# 45. Security Group Creation

Source material:

```spl
index=* eventName=CreateSecurityGroup
```

Better AWS-specific version:

```spl
index=aws eventName=CreateSecurityGroup
| table _time userIdentity.userName sourceIPAddress requestParameters responseElements
```

---

# 46. Security Group Ingress Changes

```spl
index=aws eventName=AuthorizeSecurityGroupIngress
| table _time userIdentity.userName sourceIPAddress requestParameters
```

---

# 47. Security Group Rule Modification

```spl
index=aws eventName=ModifySecurityGroupRules
| table _time userIdentity.userName sourceIPAddress requestParameters
```

---

# 48. Public SSH Exposure

Hunt for:

```text
TCP
22
0.0.0.0/0
```

Conceptually:

```spl
index=aws
| search eventName IN (AuthorizeSecurityGroupIngress,ModifySecurityGroupRules)
| search "0.0.0.0/0"
| search "22"
| table _time userIdentity.userName sourceIPAddress eventName requestParameters
```

---

# 49. Public RDP Exposure

```spl
index=aws
| search eventName IN (AuthorizeSecurityGroupIngress,ModifySecurityGroupRules)
| search "0.0.0.0/0"
| search "3389"
| table _time userIdentity.userName sourceIPAddress eventName requestParameters
```

---

# 50. Public VNC Exposure

```spl
index=aws
| search eventName IN (AuthorizeSecurityGroupIngress,ModifySecurityGroupRules)
| search "0.0.0.0/0"
| search "5900"
| table _time userIdentity.userName sourceIPAddress eventName requestParameters
```

---

# 51. Create SG → Insecure Rule

```spl
index=aws eventName IN (CreateSecurityGroup,AuthorizeSecurityGroupIngress)
| sort _time
| table _time eventName userIdentity.userName sourceIPAddress requestParameters responseElements
```

Then correlate the SG ID.

---

# 52. Find EC2 Instances Using a Security Group

Source material:

```spl
index=* eventName IN(RunInstances, ModifyInstanceAttribute) sg-xxxxxx
```

AWS-specific:

```spl
index=aws eventName IN (RunInstances,ModifyInstanceAttribute)
| search "sg-xxxxxx"
| table _time eventName userIdentity.userName sourceIPAddress requestParameters responseElements
```

---

# 53. EC2 Instance Launch

```spl
index=aws eventName=RunInstances
| table _time userIdentity.userName sourceIPAddress userAgent requestParameters responseElements
```

---

# 54. EC2 Launch From Suspicious User

```spl
index=aws eventName=RunInstances
| stats count by userIdentity.userName sourceIPAddress userAgent
| sort -count
```

Look for:

```text
New user
New IP
New user-agent
Unexpected region
```

---

# 55. EC2 Security Group Investigation Chain

```text
CreateSecurityGroup
        ↓
AuthorizeSecurityGroupIngress
        ↓
RunInstances
        ↓
Instance becomes Internet exposed
        ↓
Port scan / brute force
        ↓
Endpoint compromise
```

This is a **great correlation rule**.

---

# 🗄️ RDS / DATABASE EXPOSURE

# 56. RDS Creation

```spl
index=aws eventName=CreateDBInstance
| table _time userIdentity.userName sourceIPAddress requestParameters responseElements
```

---

# 57. RDS Modification

```spl
index=aws eventName=ModifyDBInstance
| table _time userIdentity.userName sourceIPAddress requestParameters
```

---

# 58. RDS Public Access

```spl
index=aws eventName IN (CreateDBInstance,ModifyDBInstance)
| search "PubliclyAccessible"
| table _time userIdentity.userName eventName sourceIPAddress requestParameters
```

---

# 59. RDS Security Group Changes

```spl
index=aws
| search eventName IN (
    AuthorizeSecurityGroupIngress,
    ModifySecurityGroupRules
)
| search "3306"
| table _time userIdentity.userName sourceIPAddress eventName requestParameters
```

For PostgreSQL:

```spl
index=aws
| search eventName IN (
    AuthorizeSecurityGroupIngress,
    ModifySecurityGroupRules
)
| search "5432"
| table _time userIdentity.userName sourceIPAddress eventName requestParameters
```

---

# 60. RDS Deletion

```spl
index=aws eventName=DeleteDBInstance
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

High-value destructive-action detection.

---

# 🔎 CLOUD DISCOVERY

# 61. `GetCallerIdentity`

AWS equivalent of:

```text
whoami
```

Query:

```spl
index=aws eventName=GetCallerIdentity
| table _time userIdentity.arn sourceIPAddress userAgent
```

---

# 62. IAM Discovery

```spl
index=aws eventName IN (
    GetUser,
    ListUsers,
    ListGroupsForUser,
    ListAttachedUserPolicies,
    ListUserPolicies,
    ListAccessKeys
)
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters
```

---

# 63. Account Discovery

```spl
index=aws eventName IN (
    GetAccountSummary,
    GetAccountAuthorizationDetails
)
| table _time userIdentity.arn eventName sourceIPAddress userAgent
```

---

# 64. S3 Discovery

```spl
index=aws eventName IN (
    ListBuckets,
    GetBucketLocation,
    GetBucketPolicy,
    GetBucketAcl
)
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters
```

---

# 65. EC2 Discovery

```spl
index=aws eventName IN (
    DescribeInstances,
    DescribeSecurityGroups,
    DescribeSubnets,
    DescribeVpcs,
    DescribeVolumes
)
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters
```

---

# 66. Lambda Discovery

```spl
index=aws eventName IN (
    ListFunctions,
    GetFunction,
    GetFunctionConfiguration,
    ListLayers
)
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters
```

---

# 67. Broad Discovery Detection

This is one of the best hunting queries from the material conceptually.

```spl
index=aws
| search eventName IN (
    ListBuckets,
    DescribeInstances,
    ListFunctions,
    ListUsers,
    GetAccountSummary,
    GetCallerIdentity,
    DescribeSecurityGroups,
    ListRoles,
    ListAccessKeys
)
| bin _time span=15m
| stats
    dc(eventName) as distinct_events
    dc(eventSource) as distinct_services
    count
    by _time userIdentity.arn sourceIPAddress userIdentity.accessKeyId
| where distinct_events >= 5 AND distinct_services >= 3
| sort -distinct_events
```

### Why this works

An attacker often does:

```text
Who am I?
 ↓
What permissions do I have?
 ↓
What users exist?
 ↓
What EC2 exists?
 ↓
What S3 exists?
 ↓
What Lambda exists?
```

A legitimate user usually doesn't enumerate everything across multiple services in a short period.

---

# 68. Kali / CLI Discovery

The material shows:

```text
userAgent = aws-cli/... Kali
```

Hunt:

```spl
index=aws
| search userAgent="aws-cli*"
| stats count by userIdentity.arn sourceIPAddress userAgent
| sort -count
```

**Important:** AWS CLI itself is not malicious.

You are hunting:

```text
unexpected user
+
unexpected IP
+
CLI
+
discovery
```

---

# 69. Suspicious EC2 Search Terms

The material specifically demonstrates searches for:

```text
secret
vault
```

Hunt:

```spl
index=aws eventName=DescribeInstances
| search "secret" OR "vault"
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 70. First-Seen API Calls

A useful threat-hunting idea:

```spl
index=aws
| stats earliest(_time) as firstSeen latest(_time) as lastSeen count by userIdentity.arn eventSource eventName
| sort firstSeen
```

You can then focus on:

```text
First seen
+
privileged API
+
unusual user
```

---

# 🧨 DESTRUCTIVE ACTIONS

# 71. Destructive API Hunting

```spl
index=aws eventName IN (
    DeleteUser,
    DeleteAccessKey,
    DeleteRole,
    DeleteBucket,
    DeleteObject,
    DeleteDBInstance,
    TerminateInstances,
    StopInstances,
    RevokeSecurityGroupIngress,
    DeleteFunction
)
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters
```

---

# 72. EC2 Termination

```spl
index=aws eventName=TerminateInstances
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 73. Mass EC2 Termination

```spl
index=aws eventName=TerminateInstances
| bin _time span=10m
| stats count by _time userIdentity.arn sourceIPAddress
| where count >= 5
| sort -count
```

Tune the threshold for your environment.

---

# 74. Mass S3 Deletion

```spl
index=aws eventName=DeleteObject
| bin _time span=10m
| stats count by _time userIdentity.arn sourceIPAddress requestParameters.bucketName
| where count >= 50
| sort -count
```

---

# 75. Mass Database Destruction

```spl
index=aws eventName IN (
    DeleteDBInstance,
    DeleteDBCluster
)
| table _time userIdentity.arn sourceIPAddress eventName requestParameters
```

---

# 🛠️ SSM THREAT HUNTING

# 76. All SSM Commands

```spl
index=aws eventName=SendCommand
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters responseElements
```

---

# 77. SSM From New IP

```spl
index=aws eventName=SendCommand
| stats count by userIdentity.arn sourceIPAddress
| sort userIdentity.arn -count
```

Compare against known administrative IPs.

---

# 78. SSM Targeting Many Instances

```spl
index=aws eventName=SendCommand
| bin _time span=10m
| stats dc(requestParameters.instanceIds{}) as instances count by _time userIdentity.arn sourceIPAddress
| where instances >= 5
| sort -instances
```

Depending on your field extraction, `instanceIds{}` may have a different name.

Concept:

```text
One user
 ↓
Many EC2 targets
 ↓
Short time
```

is highly interesting.

---

# 79. Session Manager

```spl
index=aws eventName=StartSession
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 80. SSM + IAM Correlation

Hunt for:

```text
CreateAccessKey
      ↓
SendCommand
```

Conceptually:

```spl
index=aws eventName IN (CreateAccessKey,SendCommand)
| sort _time
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters
```

For production, correlate by identity within a defined time window.

---

# 🛡️ GUARDDUTY

# 81. GuardDuty Findings

If GuardDuty logs are indexed:

```spl
index=aws sourcetype=*guardduty*
| table _time Severity Type Title AccountId Resource Service
```

---

# 82. High-Severity GuardDuty

```spl
index=aws sourcetype=*guardduty*
| where Severity >= 7
| table _time Severity Type Title AccountId Resource
| sort -Severity
```

---

# 83. S3 GuardDuty Findings

```spl
index=aws sourcetype=*guardduty*
| search Type="Policy:S3/*" OR Type="Impact:S3/*"
| table _time Severity Type Title Resource
```

---

# 84. EC2 GuardDuty Findings

```spl
index=aws sourcetype=*guardduty*
| search Type="Recon:EC2/*" OR Type="UnauthorizedAccess:EC2/*" OR Type="Impact:EC2/*"
| table _time Severity Type Title Resource
```

---

# 85. Cryptocurrency Mining

```spl
index=aws sourcetype=*guardduty*
| search Type="*Bitcoin*" OR Title="*cryptocurrency*"
| table _time Severity Type Title Resource
```

---

# 🌐 VPC FLOW LOGS

# 86. Basic VPC Flow Logs

```spl
index=vpc
| table _time srcaddr dstaddr srcport dstport protocol action account-id vpc-id interface-id
```

---

# 87. Rejected Traffic

```spl
index=vpc action=REJECT
| stats count by srcaddr dstaddr dstport
| sort -count
```

---

# 88. Accepted Traffic

```spl
index=vpc action=ACCEPT
| stats count by srcaddr dstaddr dstport
| sort -count
```

---

# 89. SSH Connections

```spl
index=vpc dstport=22
| stats count by srcaddr dstaddr action
| sort -count
```

---

# 90. RDP Connections

```spl
index=vpc dstport=3389
| stats count by srcaddr dstaddr action
| sort -count
```

---

# 91. VNC

```spl
index=vpc dstport=5900
| stats count by srcaddr dstaddr action
| sort -count
```

---

# 92. Port Scanning

Look for one source touching many destination ports:

```spl
index=vpc action=REJECT
| bin _time span=5m
| stats dc(dstport) as unique_ports count by _time srcaddr
| where unique_ports >= 20
| sort -unique_ports
```

---

# 93. Horizontal Scanning

One source contacting many hosts:

```spl
index=vpc
| bin _time span=5m
| stats dc(dstaddr) as unique_hosts count by _time srcaddr dstport
| where unique_hosts >= 20
| sort -unique_hosts
```

---

# 94. Possible Data Exfiltration

Large outbound connections:

```spl
index=vpc action=ACCEPT
| stats sum(bytes) as total_bytes count by srcaddr dstaddr
| sort -total_bytes
```

Then convert:

```spl
| eval GB=round(total_bytes/1024/1024/1024,2)
```

Full:

```spl
index=vpc action=ACCEPT
| stats sum(bytes) as total_bytes count by srcaddr dstaddr
| eval GB=round(total_bytes/1024/1024/1024,2)
| sort -GB
```

---

# 🌎 CLOUDFRONT

# 95. HTTP Requests

```spl
index=cloudfront
| table _time c_ip cs_method cs_host cs_uri_stem sc_status cs_user_agent
```

---

# 96. HTTP Errors

```spl
index=cloudfront
| stats count by sc_status cs_uri_stem
| sort -count
```

---

# 97. Possible Web Scanning

```spl
index=cloudfront
| bin _time span=5m
| stats dc(cs_uri_stem) as unique_urls count by _time c_ip
| where unique_urls >= 50
| sort -unique_urls
```

---

# 98. HTTP POST Spike

```spl
index=cloudfront cs_method=POST
| bin _time span=5m
| stats count by _time c_ip cs_uri_stem
| sort -count
```

---

# 99. Suspicious HTTP User Agents

```spl
index=cloudfront
| search cs_user_agent="*sqlmap*" OR cs_user_agent="*nikto*" OR cs_user_agent="*nmap*"
| table _time c_ip cs_method cs_uri_stem cs_user_agent sc_status
```

Don't treat these as automatically malicious; validate against your authorized scanners.

---

# 🐳 FALCO / CONTAINER HUNTING

# 100. Basic Falco

```spl
index=task3
| rename output_fields.* as *
| table _time user.name proc.cmdline proc.pcmdline proc.exepath proc.pexepath container.id container.name container.image
```

---

# 101. Shell Spawned by Web Server

```spl
index=task3
| rename output_fields.* as *
| search proc.pcmdline="*apache*" OR proc.pcmdline="*nginx*" OR proc.pcmdline="*httpd*"
| search proc.cmdline="*sh*" OR proc.cmdline="*bash*" OR proc.cmdline="*zsh*"
| table _time user.name proc.cmdline proc.pcmdline container.name container.image
```

This is a **high-value behavioral hunt**.

---

# 102. Suspicious Discovery Commands

```spl
index=task3
| rename output_fields.* as *
| search proc.cmdline="*find *"
    OR proc.cmdline="*whoami*"
    OR proc.cmdline="*id*"
    OR proc.cmdline="*uname*"
    OR proc.cmdline="*ps *"
    OR proc.cmdline="*ip addr*"
| table _time user.name proc.cmdline proc.pcmdline container.name container.image
```

---

# 103. Credential Hunting Commands

```spl
index=task3
| rename output_fields.* as *
| search proc.cmdline="*passwd*"
    OR proc.cmdline="*shadow*"
    OR proc.cmdline="*private*key*"
    OR proc.cmdline="*secret*"
    OR proc.cmdline="*credential*"
| table _time user.name proc.cmdline proc.pcmdline container.name container.image
```

---

# 104. Download Tools Inside Containers

```spl
index=task3
| rename output_fields.* as *
| search proc.cmdline="*wget*"
    OR proc.cmdline="*curl*"
    OR proc.cmdline="*nc *"
| table _time user.name proc.cmdline proc.pcmdline container.name container.image
```

---

# 105. Shell From Application

```spl
index=task3
| rename output_fields.* as *
| search
    (proc.pcmdline="*apache*" OR proc.pcmdline="*nginx*" OR proc.pcmdline="*php*")
    AND
    (proc.cmdline="*bash*" OR proc.cmdline="*sh *")
| table _time user.name proc.pid proc.cmdline proc.pcmdline container.name container.image
```

---

# 106. Root Activity Inside Containers

```spl
index=task3
| rename output_fields.* as *
| search user.name=root
| stats count by container.name container.image proc.cmdline
| sort -count
```

---

# 107. Container Context

```spl
index=task3
| rename output_fields.* as *
| stats count by container.name container.image proc.cmdline
| sort -count
```

Useful for baseline creation.

---

# ⚡ LAMBDA THREAT HUNTING

# 108. All Lambda Changes

```spl
index=aws eventSource=lambda.amazonaws.com readOnly=false
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters responseElements
```

---

# 109. Lambda Code Modification

```spl
index=aws eventName=UpdateFunctionCode*
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 110. Lambda Configuration Modification

```spl
index=aws eventName=UpdateFunctionConfiguration*
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 111. Lambda Permission Changes

```spl
index=aws eventName=AddPermission*
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 112. Public Lambda Permission

Search for:

```text
Principal = *
```

```spl
index=aws eventName=AddPermission*
| search "Principal"="*"
| table _time userIdentity.arn sourceIPAddress requestParameters
```

Again, inspect conditions and context before declaring it malicious.

---

# 113. Lambda Layers

```spl
index=aws eventName=PublishLayerVersion*
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters
```

---

# 114. New Lambda Functions

```spl
index=aws eventName=CreateFunction*
| table _time userIdentity.arn sourceIPAddress userAgent requestParameters responseElements
```

---

# 115. Lambda Powerful Role Assignment

```spl
index=aws eventName=UpdateFunctionConfiguration*
| search "AdministratorAccess"
    OR "PowerUserAccess"
    OR "FullAccess"
| table _time userIdentity.arn sourceIPAddress requestParameters
```

---

# 116. Lambda + IAM Correlation

Search Lambda modifications and role changes:

```spl
index=aws
| search eventName IN (
    UpdateFunctionCode*,
    UpdateFunctionConfiguration*,
    AttachRolePolicy,
    PutRolePolicy,
    CreateRole
)
| sort _time
| table _time userIdentity.arn eventName sourceIPAddress userAgent requestParameters
```

---

# 117. Lambda Backdoor Hunting

Look for this sequence:

```text
CreateFunction
       ↓
Role becomes powerful
       ↓
UpdateFunctionCode
       ↓
AddPermission
```

Search:

```spl
index=aws
| search eventName IN (
    CreateFunction*,
    UpdateFunctionConfiguration*,
    UpdateFunctionCode*,
    AddPermission*
)
| sort _time
| table _time userIdentity.arn eventName sourceIPAddress requestParameters
```

Then correlate by:

```text
userIdentity
functionName
time
source IP
```

---

# 💰 DENIAL OF WALLET

This deserves its own detection category.

Cloud attack ≠ only:

```text
Data theft
Malware
Account takeover
```

It can also be:

```text
ATTACKER
   ↓
Cloud resource consumption
   ↓
Huge bill
```

---

# 118. EC2 Launch Spike

```spl
index=aws eventName=RunInstances
| bin _time span=15m
| stats count as instances by _time userIdentity.arn sourceIPAddress
| where instances >= 10
| sort -instances
```

---

# 119. S3 Request Spike

```spl
index=aws eventName IN (GetObject,PutObject)
| bin _time span=10m
| stats count as requests by _time sourceIPAddress requestParameters.bucketName
| where requests >= 1000
| sort -requests
```

---

# 120. High Outbound Data

```spl
index=vpc action=ACCEPT
| stats sum(bytes) as bytes by srcaddr dstaddr
| eval GB=round(bytes/1024/1024/1024,2)
| where GB > 10
| sort -GB
```

Tune the threshold.

---

# 121. Cloud Cost Attack Correlation

Conceptually hunt:

```text
RunInstances spike
+
network traffic spike
+
SSM activity
```

```spl
index=aws
| search eventName IN (RunInstances,SendCommand,StartSession)
| bin _time span=15m
| stats count by _time eventName userIdentity.arn sourceIPAddress
| sort _time
```

---

# 🚨 MASTER CLOUD THREAT-HUNTING QUERY

When you don't know where to start:

```spl
index=aws
| search eventName IN (
    ConsoleLogin,
    CreateAccessKey,
    AssumeRole,
    CreateUser,
    AttachUserPolicy,
    AttachRolePolicy,
    PutUserPolicy,
    PutRolePolicy,
    AddUserToGroup,
    CreateSecurityGroup,
    AuthorizeSecurityGroupIngress,
    ModifySecurityGroupRules,
    RunInstances,
    TerminateInstances,
    SendCommand,
    StartSession,
    PutBucketPolicy,
    PutBucketPublicAccessBlock,
    GetObject,
    DeleteObject,
    CreateDBInstance,
    ModifyDBInstance,
    DeleteDBInstance,
    CreateFunction,
    UpdateFunctionCode,
    UpdateFunctionConfiguration,
    AddPermission,
    PublishLayerVersion
)
| stats count by eventName userIdentity.arn sourceIPAddress userAgent
| sort -count
```

This gives you a **high-risk AWS activity overview**.

---

# 🧠 MASTER CLOUD SOC INVESTIGATION FLOW

When an alert comes into Splunk:

```text
                 ALERT
                   ↓
             WHAT HAPPENED?
                   ↓
              eventName
                   ↓
              WHO DID IT?
                   ↓
            userIdentity.*
                   ↓
             FROM WHERE?
                   ↓
           sourceIPAddress
                   ↓
             HOW?
                   ↓
             userAgent
                   ↓
             WHAT RESOURCE?
                   ↓
          requestParameters
                   ↓
            WHAT CHANGED?
                   ↓
          responseElements
                   ↓
          WHAT HAPPENED NEXT?
                   ↓
      CloudTrail + VPC + S3 + EDR
                   ↓
              IMPACT?
```

---

# 🔥 HIGH-PRIORITY DETECTIONS TO BUILD

If you're building a real SOC dashboard, **don't create 200 alerts immediately**. Start with these.

|Priority|Detection|
|--:|---|
|🔴 1|Root login|
|🔴 2|Root access-key creation|
|🔴 3|`CreateAccessKey`|
|🔴 4|`AdministratorAccess` attachment|
|🔴 5|MFA disabled|
|🔴 6|Suspicious `AssumeRole`|
|🔴 7|Public S3 exposure|
|🔴 8|Public SSH/RDP|
|🔴 9|RDS public exposure|
|🔴 10|Suspicious `SendCommand`|
|🔴 11|Suspicious `StartSession`|
|🔴 12|Lambda code modification|
|🔴 13|Lambda powerful execution role|
|🔴 14|Lambda public permission|
|🟠 15|Broad AWS discovery|
|🟠 16|Port scanning|
|🟠 17|S3 object enumeration|
|🟠 18|Mass S3 download|
|🟠 19|Mass EC2 creation|
|🟠 20|Container web-server → shell|

---

# 📊 THE AWS SOC DASHBOARD

If you eventually build a Splunk dashboard, I'd structure it like this:

```text
┌─────────────────────────────────────────────────────────┐
│              AWS CLOUD SECURITY SOC                     │
├──────────────┬──────────────┬──────────────┬───────────┤
│ Root Logins  │ IAM Changes  │ S3 Exposure  │ GuardDuty │
├──────────────┼──────────────┼──────────────┼───────────┤
│ Public SGs   │ RDS Exposure │ Lambda Mods  │ SSM       │
├─────────────────────────────────────────────────────────┤
│                    TOP USERS                             │
├─────────────────────────────────────────────────────────┤
│                    TOP SOURCE IPs                       │
├─────────────────────────────────────────────────────────┤
│                 DISCOVERY ACTIVITY                      │
├─────────────────────────────────────────────────────────┤
│              NETWORK ANOMALIES                          │
├─────────────────────────────────────────────────────────┤
│              CONTAINER RUNTIME                          │
├─────────────────────────────────────────────────────────┤
│                HIGH-RISK EVENTS                         │
└─────────────────────────────────────────────────────────┘
```

---

# 🧩 FINAL MEMORY MAP

Don't try to memorize every query individually. Memorize the **AWS attack surface**:

```text
                     AWS
                      │
       ┌──────────────┼──────────────┐
       ↓              ↓              ↓
     IAM             EC2            S3
       │              │              │
       ↓              ↓              ↓
 Credentials      SG / SSH       Public bucket
 Roles            SSM            Object access
 MFA              Runtime        Exfiltration
       │              │              │
       └──────────────┼──────────────┘
                      ↓
                  DATABASE
                      │
                     RDS
                      │
                 Public access
                      │
                      ↓
                  LAMBDA
                      │
              Code / Role / Trust
                      │
                      ↓
                CONTAINERS
                      │
                 Falco / EDR
                      │
                      ↓
                  NETWORK
                      │
              VPC Flow / DNS
                      │
                      ↓
                   SPLUNK
                      │
        ┌─────────────┼──────────────┐
        ↓             ↓              ↓
      Detect        Hunt          Correlate
        ↓             ↓              ↓
                  SOC L2
```

## ⭐ The 10 queries I'd memorize first

```spl
# 1. Root login
index=aws eventName=ConsoleLogin userIdentity.type=Root

# 2. Access-key creation
index=aws eventName=CreateAccessKey

# 3. Privilege escalation
index=aws eventName IN (AttachUserPolicy,AttachRolePolicy,AttachGroupPolicy,PutUserPolicy,PutRolePolicy,PutGroupPolicy)

# 4. Role assumption
index=aws eventName=AssumeRole

# 5. Public S3 policy
index=aws eventName=PutBucketPolicy

# 6. Public SG changes
index=aws eventName IN (AuthorizeSecurityGroupIngress,ModifySecurityGroupRules)

# 7. SSM remote execution
index=aws eventName=SendCommand

# 8. Session Manager access
index=aws eventName=StartSession

# 9. Lambda modifications
index=aws eventSource=lambda.amazonaws.com readOnly=false

# 10. Broad cloud discovery
index=aws eventName IN (GetCallerIdentity,ListUsers,ListBuckets,DescribeInstances,ListFunctions,GetAccountSummary)
```

**One correction worth keeping in your mental model:** don't treat `readOnly=false` as synonymous with "malicious." It means the event is classified as a write/non-read operation. Plenty of legitimate administrative activity falls into that bucket. The SOC job is to combine **identity + baseline + resource + source + timing + sequence + impact**.

This is the difference between a **Splunk query collector** and a **SOC analyst who can actually hunt AWS**.
---
