# Nintendo Cloud Security Engineer: Technical Prep

**Tuesday, May 26 — 90 minutes with the security engineering team.** This isn't a trivia quiz. They'll walk you through a live incident scenario for a NOA-like company (multi-department AWS environment with customer-facing web services), show you real GuardDuty/Wiz screenshots, and ask you to work through triage, prioritization, and remediation out loud. CoderPad is included for you to demo scripting — think quick Python/Bash to solve a problem they surface, not a LeetCode exercise. The recruiter says the team keeps it light (top-tier memes), so treat it as a working session, not a grilling. Below is prep organized around their six evaluation criteria.

| Detail | Value |
| --- | --- |
| Interview Length | 90 min with security engineering team |
| Core Format | 1 incident, GuardDuty/Wiz triggered |
| Scripting Demo | CoderPad — Python/Bash expected |
| Evaluation Criteria | 6 areas listed by recruiter |

## Table of contents

- [How to Approach the Live Incident](#how-to-approach-the-live-incident)
- [1. AWS GuardDuty](#1-aws-guardduty)
- [2. AWS CloudTrail](#2-aws-cloudtrail)
- [3. Security Group Traffic](#3-security-group-traffic)
- [4. AWS S3](#4-aws-s3)
- [5. Identity & Access Management](#5-identity--access-management)
- [6. Secure Communication & Connectivity](#6-secure-communication--connectivity)
- [Putting It Together: A Practice Incident](#putting-it-together-a-practice-incident)
- [CoderPad: Python Snippets](#coderpad-python-snippets)
- [Prevention: Service Control Policies](#prevention-service-control-policies)
- [Nintendo-Specific Angles](#nintendo-specific-angles)
- [Reference: The Capital One Breach](#reference-the-capital-one-breach)

---

## How to Approach the Live Incident

### Think Out Loud, in Layers

They're evaluating your thought process, not checking off a rubric of AWS service names.

When they show you the incident screenshots, use this mental model:
1. **Orient:** Read the GuardDuty/Wiz finding. State what type of alert it is (e.g., "This is a `Recon:EC2/PortProbeUnprotectedPort` finding — someone is probing an exposed port"). Ask clarifying questions about the environment: how many accounts, what services are in scope, what logging exists.
2. **Prioritize:** Assess severity. Is this active exploitation or a misconfiguration? What's the blast radius — is sensitive data (customer PII, game IP) reachable from the affected resource? Name what you'd triage first and why.
3. **Contain:** Describe immediate actions — isolate the resource, revoke credentials, preserve evidence. Be specific about which AWS actions you'd take.
4. **Investigate:** Walk through your evidence chain — CloudTrail for API activity, VPC Flow Logs for network, S3 access logs for data exfil. Connect findings across the six evaluation areas.
5. **Remediate & Harden:** Fix the root cause, then propose preventive controls so it doesn't recur. This is where you show systems thinking. Draw from your Sony incident experience here. When they say "how would you handle this," anchor in a real story: "At Sony, we had a similar situation where..." then map it to the scenario they've presented.

---

## 1. AWS GuardDuty

> **What They'll Evaluate (from recruiter):** Keeping agents/services enabled for threat detection. Gaps in monitoring coverage.

### Core Knowledge
- **What it analyzes:** CloudTrail management & data events, VPC Flow Logs, DNS query logs, EKS audit logs, S3 data events, Lambda network activity, and RDS login events. These are *protection plans* you can individually enable.
- **Common gap:** GuardDuty is enabled but S3 Protection or EKS Protection is off — the org thinks they're covered, but entire data planes are unmonitored. If they show you an incident and ask "why didn't we catch this sooner," check which protection plans are active.
- **Finding types to know cold:**
  - `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — EC2 role credentials used from outside AWS
  - `Recon:EC2/PortProbeUnprotectedPort` — open port being scanned
  - `Trojan:EC2/C&CActivity.B` — instance calling a C2 server
  - `Policy:S3/BucketPublicAccessGranted` — bucket made public
  - `Stealth:S3/ServerAccessLoggingDisabled` — logging turned off (covering tracks)
- **Multi-account:** Use delegated admin in AWS Organizations so GuardDuty findings aggregate to a central security account. If they have departments using separate AWS accounts, this is likely their setup.
- **Runtime Monitoring:** GuardDuty agent deployed to EC2/EKS/ECS for process-level visibility (file access, network connections, process execution). If not enabled, you have a blind spot between "API-level detection" and "what actually ran on the host."

### What to Say in the Interview

When they show the GuardDuty screenshot, read the finding type, severity, affected resource, and actor. Then say something like: *"First question — is this finding from a protection plan that's actively monitored, or did we get lucky? I'd want to audit which GuardDuty features are enabled across all accounts to make sure we don't have coverage gaps."* This shows you think beyond the single alert.

---

## 2. AWS CloudTrail

> **What They'll Evaluate (from recruiter):** Enabling and retaining audit logs. Using logs for investigations, compliance, and incident response.

### Core Knowledge
- **Trail types:** Management events (API calls like `RunInstances`, `CreateBucket`) are enabled by default. Data events (S3 `GetObject`/`PutObject`, Lambda invocations) are *not* — these must be explicitly enabled and cost more, but they're critical for investigating data exfil.
- **Organization trail:** A single trail in the management account captures events from all member accounts. The incident scenario is multi-department, so expect this to be relevant.
- **Retention matters:** Default console view is 90 days. For compliance and IR, send events to an S3 bucket with lifecycle policies (keep 1+ year) and to CloudWatch Logs or a SIEM for real-time alerting. If they ask about compliance, mention that SOC 2 and PCI-DSS require durable audit logs.
- **Log integrity:** Enable CloudTrail log file validation (digest files) so you can prove logs haven't been tampered with. If an attacker disables CloudTrail (`StopLogging`), GuardDuty detects it as `Stealth:IAMUser/CloudTrailLoggingDisabled`.
- **Key fields for investigation:** `eventName`, `userIdentity` (who), `sourceIPAddress` (where), `requestParameters` (what), `eventTime` (when). Filter by access key ID to trace all actions from a specific credential.
- **Athena for querying:** Create an Athena table over CloudTrail logs in S3 to run SQL queries during an investigation. Fast for questions like "show me all S3 API calls from this IP in the last 72 hours."

### CoderPad Angle

If they ask you to script something, a CloudTrail log parser is likely. Something like: "Given these CloudTrail JSON events, find all API calls made by a specific access key ID after a given timestamp." This is straightforward Python — `json.load`, filter by `userIdentity.accessKeyId` and `eventTime`, print results.

---

## 3. Security Group Traffic

> **What They'll Evaluate (from recruiter):** Best practices for traffic rules. Risks of overly permissive rules. Principles of least privilege for network access. CIDR ranges and exposure risks.

### Core Knowledge
- **Security groups are stateful firewalls.** If inbound is allowed, the return traffic is automatically allowed. NACLs are stateless (both directions must be explicitly allowed).
- **The red flag:** Inbound rule with `0.0.0.0/0` on port 22 (SSH) or 3389 (RDP). This is the most common misconfiguration they'll test. In the incident scenario, an open port may be the entry point.
- **Least privilege for SGs:** Reference other security groups instead of CIDR ranges when possible (e.g., "allow inbound 443 from the ALB security group" rather than a /16 block). Use specific CIDR ranges only for known external IPs (VPN, office).
- **CIDR risk assessment:** `/32` = single host (good). `/24` = 256 IPs. `/16` = 65K IPs. `/0` = the entire internet (almost never appropriate for inbound). Know that `0.0.0.0/0` is IPv4 "everywhere" and `::/0` is IPv6 "everywhere" — both must be locked down.
- **Outbound controls:** Default SG allows all outbound traffic. In a security-conscious environment, restrict outbound to necessary ports (443 for HTTPS, specific endpoints). This limits data exfil and C2 callbacks. If the incident involves an EC2 calling out to a malicious IP, unrestricted egress is the root cause.
- **Containment technique:** During an incident, swap the compromised instance's SG to a pre-staged "quarantine" group that denies all inbound/outbound. This isolates without terminating (preserves forensic evidence).

### CoderPad Angle

Possible scripting ask: "Write a script to find all security groups with inbound rules open to `0.0.0.0/0`." This is a boto3 one-liner pattern — `describe_security_groups`, iterate rules, check for `0.0.0.0/0` in `IpRanges`. Quick and clean.

---

## 4. AWS S3

> **What They'll Evaluate (from recruiter):** Securing S3 buckets/cloud storage. Read/write access across accounts. Encryption, access policies, and data exposure risks.

### Core Knowledge
- **Public access controls:** S3 Block Public Access settings exist at both the account level and bucket level. Account-level BPA should be on by default — if a bucket is public, it means someone deliberately (or accidentally) overrode it. Wiz flags this aggressively.
- **Bucket policies vs. ACLs:** Modern best practice is to disable ACLs entirely (bucket owner enforced) and use bucket policies for all access control. ACLs are legacy and hard to audit. If the scenario shows an ACL granting access, call it out as a misconfiguration.
- **Cross-account access:** In a multi-department setup, departments share S3 data via bucket policies with `Principal` set to a specific account/role ARN. The risk: overly broad principals (`"Principal": "*"` or `"Principal": {"AWS": "*"}`). Always scope to specific accounts, roles, and add `aws:PrincipalOrgID` conditions.
- **Encryption:** SSE-S3 (Amazon-managed keys) is the default since Jan 2023. SSE-KMS gives you key management, audit trails via CloudTrail, and the ability to restrict decryption by IAM policy. For sensitive data, SSE-KMS with a customer-managed key (CMK) is the standard.
- **Data exfil detection:** Enable S3 server access logging or CloudTrail data events for S3. Look for unusual `GetObject` volume, access from unfamiliar IPs, or bulk downloads. GuardDuty's S3 protection detects anomalous access patterns.
- **VPC endpoints:** Use S3 gateway endpoints with endpoint policies to ensure buckets are only accessible from within the VPC — not over the public internet. This is a data perimeter control.

---

## 5. Identity & Access Management

> **What They'll Evaluate (from recruiter):** IAM role/policies and least privilege design. Attaching roles to compute resources/instances. Managed policies, like Systems Manager access.

### Core Knowledge
- **Roles on compute:** EC2 instances, Lambda functions, and ECS tasks should use IAM roles (via instance profiles or task roles), never long-lived access keys. The role provides short-term credentials from IMDS (EC2) or the container credential provider (ECS). If the incident involves static keys on an instance, flag it.
- **Systems Manager (SSM):** The recruiter called this out specifically. The `AmazonSSMManagedInstanceCore` managed policy allows SSM Agent to communicate with Systems Manager — this is how you get Session Manager access (replaces SSH), patch management, and inventory. The risk: this policy also allows `ssm:SendCommand` which can execute arbitrary commands on instances. Scope it tightly.
- **Least privilege design:** Start with zero permissions and add. Use IAM Access Analyzer to generate policies from CloudTrail activity. Scope resources to specific ARNs (not `*`). Add conditions: `aws:SourceVpc`, `aws:RequestedRegion`, `aws:PrincipalTag`.
- **Policy evaluation order:** Implicit deny → SCPs → Resource policies → Permission boundaries → Session policies → Identity policies. Explicit deny always wins.
- **Privilege escalation patterns:** `iam:PassRole` + compute creation (EC2/Lambda) is the most common. `iam:CreatePolicyVersion` with `--set-as-default` is the sneakiest. `iam:AttachRolePolicy` to grant AdministratorAccess is the loudest (easy to detect in CloudTrail).
- **Revoking active sessions:** Attach an inline deny-all policy with condition `aws:TokenIssueTime` before the current timestamp. All existing sessions are denied; new assumptions work normally.

### CoderPad Angle

Possible ask: "Find all IAM roles with AdministratorAccess attached" or "List all roles that haven't been used in 90 days." Both are `boto3` scripts — `list_roles()` → `list_attached_role_policies()`, or `get_role()` → check `RoleLastUsed`.

---

## 6. Secure Communication & Connectivity

> **What They'll Evaluate (from recruiter):** Proper use of secure ports/protocols like HTTPS. Controlling outbound access and restricting unnecessary connectivity.

### Core Knowledge
- **Enforce HTTPS everywhere:** S3 bucket policies should include a `Deny` statement with condition `"aws:SecureTransport": "false"` to block HTTP. ALBs and CloudFront distributions should redirect HTTP → HTTPS. TLS 1.2+ minimum.
- **Outbound restriction:** Default security groups allow all egress. Lock this down to only necessary destinations: port 443 for HTTPS to known endpoints, NTP (port 123), DNS (port 53). Use VPC endpoints for AWS services (S3, SSM, CloudWatch) to keep traffic off the public internet entirely.
- **Why outbound matters:** Unrestricted egress is how data gets exfiltrated and how compromised instances reach C2 servers. If the incident shows an EC2 instance calling out to an unknown IP on port 443, the question is "why was this allowed?" The answer: no egress filtering.
- **NAT Gateway vs. VPC Endpoints:** NAT Gateways route all outbound to the internet — you can see the traffic in Flow Logs but can't restrict by destination. VPC endpoints are direct, private connections to specific AWS services with their own access policies. Prefer endpoints for AWS API traffic.
- **SSH / RDP elimination:** Use SSM Session Manager instead of opening port 22/3389. Sessions are logged, auditable, and don't require inbound SG rules. This connects back to the SSM managed policy discussion in the IAM section.
- **Network segmentation:** In a multi-department company like the scenario describes, use separate VPCs or subnets per department with VPC peering or Transit Gateway. Security groups and NACLs enforce inter-department boundaries. Private subnets for compute, public subnets only for load balancers.

---

## Putting It Together: A Practice Incident

### Scenario: Wiz alerts on a public S3 bucket; GuardDuty flags credential exfiltration

Based on the recruiter's description, here's a plausible incident that ties all six evaluation areas together. Practice narrating your response aloud.

- **Alert:** Wiz flags an S3 bucket in the data analytics department's account as publicly accessible. Minutes later, GuardDuty fires `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — an EC2 role's credentials are being used from an external IP.
- **Triage (GuardDuty + S3):** Correlate the two alerts. The EC2 instance has an IAM role with broad S3 read access. The instance is in a public subnet with a security group allowing inbound `0.0.0.0/0` on port 80. Check: does it have IMDSv2 enforced? If `HttpTokens: optional`, an SSRF against the web app on port 80 could have harvested credentials from IMDSv1.
- **Contain (SG + IAM):** Swap the instance's security group to a quarantine SG (deny all in/out). Revoke the role's active sessions using a deny policy with `aws:TokenIssueTime` condition. Snapshot the EBS volume for forensics.
- **Investigate (CloudTrail):** Query CloudTrail for all API calls made by the compromised role's access key in the last 72 hours. Look for: `ListBuckets`, `GetObject` (data exfil), `CreateAccessKey` (persistence), any IAM modifications. Check VPC Flow Logs for the external IP that used the stolen credentials.
- **Remediate (all six areas):**
  - **S3:** Enable account-level Block Public Access. Fix the bucket policy. Enable SSE-KMS.
  - **IAM:** Scope the role to specific bucket ARNs. Remove `s3:*` and replace with `s3:GetObject` on necessary resources only.
  - **SG:** Remove `0.0.0.0/0` inbound. Move the instance to a private subnet behind an ALB.
  - **IMDS:** Enforce IMDSv2 (`HttpTokens=required`) on all instances via launch templates.
  - **Connectivity:** Add S3 VPC endpoint with an endpoint policy scoped to the necessary buckets. Restrict egress in the SG.
  - **CloudTrail:** Ensure S3 data events are enabled for sensitive buckets. Verify log retention is at least 1 year.
  - **GuardDuty:** Confirm S3 Protection and Runtime Monitoring are enabled across all accounts.

---

## CoderPad: Python Snippets

The CoderPad is for demonstrating how you'd automate a response or audit — not a LeetCode test. Write clean, readable code. They care that you know the right boto3 calls and can structure a script logically. Have these patterns in your head; adapt them to whatever the scenario asks for.

### 1. Find Security Groups Open to the Internet

**When they'd ask:** The incident involves an exposed instance. "Can you write something to find all other groups with the same problem?"

```python
import boto3

# Run per region (or loop regions) for org-wide coverage
ec2 = boto3.client('ec2')

INTERNET_CIDRS_V4 = ('0.0.0.0/0',)
INTERNET_CIDRS_V6 = ('::/0',)


def _open_internet_cidrs(rule):
    """Return any internet-wide CIDRs on a single SG rule."""
    open_v4 = [
        r['CidrIp'] for r in rule.get('IpRanges', [])
        if r.get('CidrIp') in INTERNET_CIDRS_V4
    ]
    open_v6 = [
        r['CidrIpv6'] for r in rule.get('Ipv6Ranges', [])
        if r.get('CidrIpv6') in INTERNET_CIDRS_V6
    ]
    return open_v4 + open_v6


def find_open_security_groups():
    """Find SG rules allowing inbound or outbound access from the internet."""
    findings = []
    paginator = ec2.get_paginator('describe_security_groups')
    for page in paginator.paginate():
        for sg in page['SecurityGroups']:
            # Check inbound (IpPermissions) and outbound (IpPermissionsEgress)
            for direction, rules in (
                ('inbound', sg.get('IpPermissions', [])),
                ('outbound', sg.get('IpPermissionsEgress', [])),
            ):
                for rule in rules:
                    open_cidrs = _open_internet_cidrs(rule)
                    if open_cidrs:
                        findings.append({
                            'sg_id': sg['GroupId'],
                            'sg_name': sg['GroupName'],
                            'direction': direction,
                            'port': rule.get('FromPort', 'all'),
                            'protocol': rule.get('IpProtocol', 'all'),
                            'open_to': open_cidrs,
                        })
    for f in findings:
        print(f"[OPEN] {f['sg_id']} ({f['sg_name']}) {f['direction']} "
              f"port {f['port']} → {f['open_to']}")
    return findings


find_open_security_groups()
```

### 2. Find EC2 Instances Still on IMDSv1

**When they'd ask:** After discovering SSRF or credential theft via metadata. "How would you audit the rest of the fleet?"

```python
import boto3

ec2 = boto3.client('ec2')

TERMINAL_STATES = {'terminated', 'shutting-down'}


def find_imdsv1_instances():
    """Find instances where IMDSv1 is still allowed (HttpTokens != required)."""
    vulnerable = []
    paginator = ec2.get_paginator('describe_instances')
    for page in paginator.paginate():
        for res in page['Reservations']:
            for inst in res['Instances']:
                if inst['State']['Name'] in TERMINAL_STATES:
                    continue
                md = inst.get('MetadataOptions', {})
                # IMDS disabled — not reachable, not in scope for SSRF cred theft
                if md.get('HttpEndpoint') == 'disabled':
                    continue
                if md.get('HttpTokens') != 'required':
                    name = next(
                        (t['Value'] for t in inst.get('Tags', [])
                         if t['Key'] == 'Name'),
                        'unnamed',
                    )
                    entry = {
                        'instance_id': inst['InstanceId'],
                        'name': name,
                        'http_tokens': md.get('HttpTokens', 'unknown'),
                        'http_endpoint': md.get('HttpEndpoint', 'unknown'),
                        'hop_limit': md.get('HttpPutResponseHopLimit'),
                        'state': inst['State']['Name'],
                    }
                    vulnerable.append(entry)
    for v in vulnerable:
        print(f"[IMDSv1] {v['instance_id']} ({v['name']}) "
              f"HttpTokens={v['http_tokens']} hop_limit={v['hop_limit']} "
              f"state={v['state']}")
    return vulnerable


find_imdsv1_instances()
```

### 3. Quarantine a Compromised Instance

**When they'd ask:** "Show me how you'd contain this." This is probably the highest-impact script — it maps directly to the incident flow.

```python
import boto3
from datetime import datetime, timezone

# EC2 client must be in the same region as the instance
ec2 = boto3.client('ec2')


def quarantine_instance(instance_id, quarantine_sg_id):
    """Isolate an instance: snapshot volumes, swap SG, tag for IR.

    The quarantine SG must deny ALL inbound and outbound traffic.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')

    resp = ec2.describe_instances(InstanceIds=[instance_id])
    if not resp['Reservations']:
        raise ValueError(f"Instance not found: {instance_id}")

    instance = resp['Reservations'][0]['Instances'][0]
    original_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
    print(f"Original SGs: {original_sgs}")

    # STEP 1: Snapshot EBS volumes before isolation (common IR playbook).
    # Instance store volumes are not captured — note that in the interview.
    for bdm in instance.get('BlockDeviceMappings', []):
        if 'Ebs' not in bdm:
            continue
        vol_id = bdm['Ebs']['VolumeId']
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f"IR-{instance_id}-{timestamp}",
            TagSpecifications=[{
                'ResourceType': 'snapshot',
                'Tags': [
                    {'Key': 'Purpose', 'Value': 'incident-response'},
                    {'Key': 'SourceInstance', 'Value': instance_id},
                    {'Key': 'OriginalSGs', 'Value': ','.join(original_sgs)[:256]},
                ],
            }],
        )
        print(f"Snapshot created: {snap['SnapshotId']} for volume {vol_id}")

    # STEP 2: Network isolation — swap to quarantine SG (no in/out).
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg_id],
    )
    print(f"Swapped SGs to quarantine: {quarantine_sg_id}")

    # STEP 3: Tag for coordination (truncate SG list — tag value max 256 chars).
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {'Key': 'SecurityStatus', 'Value': 'quarantined'},
            {'Key': 'QuarantineTime', 'Value': timestamp},
            {'Key': 'OriginalSecurityGroups', 'Value': ','.join(original_sgs)[:256]},
        ],
    )
    print(f"Instance {instance_id} quarantined and tagged.")


quarantine_instance('i-0abc123def456', 'sg-quarantine123')
```

### 4. Investigate CloudTrail for a Compromised Access Key

**When they'd ask:** "We have the access key ID from the GuardDuty finding. What did the attacker do with it?"

```python
import boto3
from datetime import datetime, timedelta, timezone

# Use the region where the trail is configured; repeat per region or use Athena
ct = boto3.client('cloudtrail')


def investigate_access_key(access_key_id, hours_back=72):
    """Triage API activity for an access key (long-term AKIA or session ASIA).

    lookup_events is fast for initial triage but capped (~90 days, pagination).
    For full IR, pivot to CloudTrail Lake / Athena on the org trail in S3.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours_back)
    events = []
    paginator = ct.get_paginator('lookup_events')
    for page in paginator.paginate(
        LookupAttributes=[{
            'AttributeKey': 'AccessKeyId',
            'AttributeValue': access_key_id,
        }],
        StartTime=start,
        EndTime=now,
    ):
        events.extend(page['Events'])

    api_calls = {}
    for e in events:
        name = e.get('EventName', 'unknown')
        api_calls[name] = api_calls.get(name, 0) + 1

    print(f"Found {len(events)} events for key {access_key_id}")
    print("(If truncated, query Athena/Lake for complete history.)\n")
    print("API call summary:")
    for call, count in sorted(api_calls.items(), key=lambda x: -x[1]):
        print(f"  {call}: {count}")

    risky = {
        'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy',
        'PutUserPolicy', 'PutRolePolicy', 'CreatePolicyVersion',
        'RunInstances', 'CreateLoginProfile', 'UpdateAssumeRolePolicy',
        'AddUserToGroup', 'CreateUser',
        'StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutBucketPolicy',
    }
    found_risky = risky & set(api_calls.keys())
    if found_risky:
        print(f"\n⚠ HIGH-RISK API calls detected: {found_risky}")
    return events


# GuardDuty credential exfil often surfaces a session key (ASIA…), not AKIA…
investigate_access_key('ASIA1234567890EXAMPLE')
```

### 5. Re-Enable CloudTrail Logging

**When they'd ask:** GuardDuty fires `Stealth:IAMUser/CloudTrailLoggingDisabled` — an attacker (or misconfiguration) stopped logging to cover tracks. "How would you find and fix all disabled trails?"

```python
import boto3

# Call describe_trails from each region (or the trail home region) for full coverage
ct = boto3.client('cloudtrail')


def reenable_cloudtrail_logging():
    """Find trails with logging stopped and re-enable them."""
    trails = ct.describe_trails(includeShadowTrails=False)['trailList']
    fixed = []
    for trail in trails:
        trail_name = trail['Name']
        trail_arn = trail['TrailARN']
        home_region = trail.get('HomeRegion', 'unknown')
        # API expects trail name, not ARN
        status = ct.get_trail_status(Name=trail_name)
        if not status.get('IsLogging', False):
            print(f"[STOPPED] {trail_name} ({trail_arn}) region={home_region}")
            stop_time = status.get('LatestDeliveryTime', 'unknown')
            print(f"  Last delivery: {stop_time}")
            ct.start_logging(Name=trail_name)
            verify = ct.get_trail_status(Name=trail_name)
            if verify.get('IsLogging'):
                print("  ✓ Logging re-enabled and confirmed")
                fixed.append({
                    'trail': trail_name,
                    'arn': trail_arn,
                    'last_delivery': str(stop_time),
                })
            else:
                print("  ✗ Failed to re-enable — investigate manually")
        else:
            print(f"[OK] {trail_name} — logging active")

    print(f"\nResults: {len(fixed)} trail(s) re-enabled out of {len(trails)} total")
    if fixed:
        print("\nNext steps:")
        print("  1. Query CloudTrail for StopLogging — identify who disabled logging")
        print("  2. Verify log file validation (digest files) is enabled")
        print("  3. Confirm the log delivery S3 bucket exists and is accessible")
        print("  4. Assess log gaps during the disabled window (Athena/Lake)")
    return fixed


reenable_cloudtrail_logging()
```

### 6. Find Public S3 Buckets

**When they'd ask:** "The incident started with an exposed bucket. How many others are at risk?"

```python
import boto3
import json
from botocore.exceptions import ClientError

s3_global = boto3.client('s3')


def bucket_region(bucket_name):
    loc = s3_global.get_bucket_location(Bucket=bucket_name).get('LocationConstraint')
    return loc or 'us-east-1'


def iter_policy_statements(policy):
    stmt = policy.get('Statement', [])
    return [stmt] if isinstance(stmt, dict) else stmt


def is_public_principal(principal):
    if principal == '*':
        return True
    if isinstance(principal, dict):
        aws = principal.get('AWS')
        if aws == '*':
            return True
        if isinstance(aws, list) and '*' in aws:
            return True
    return False


def find_public_buckets():
    """Check buckets for public exposure (BPA, policy, ACL)."""
    public_buckets = []
    for bucket in s3_global.list_buckets()['Buckets']:
        name = bucket['Name']
        issues = []
        s3 = boto3.client('s3', region_name=bucket_region(name))
        try:
            config = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False),
            ]):
                issues.append('Block Public Access not fully enabled')
        except ClientError as err:
            code = err.response['Error']['Code']
            if code == 'NoSuchPublicAccessBlockConfiguration':
                issues.append('No Block Public Access config on bucket')
            else:
                issues.append(f'Could not read BPA: {code}')
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
            for stmt in iter_policy_statements(policy):
                if stmt.get('Effect') == 'Allow' and is_public_principal(stmt.get('Principal')):
                    issues.append(f"Policy allows public access: {stmt.get('Action')}")
        except ClientError as err:
            if err.response['Error']['Code'] != 'NoSuchBucketPolicy':
                issues.append(f'Policy read error: {err.response["Error"]["Code"]}')
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get('Grants', []):
                uri = grant.get('Grantee', {}).get('URI', '')
                if 'AllUsers' in uri:
                    issues.append(f"ACL grants anonymous access: {grant['Permission']}")
                elif 'AuthenticatedUsers' in uri:
                    issues.append(f"ACL grants authenticated AWS users: {grant['Permission']}")
        except ClientError:
            pass
        if issues:
            public_buckets.append({'bucket': name, 'issues': issues})
            for issue in issues:
                print(f"[PUBLIC] {name}: {issue}")
    if not public_buckets:
        print("No public buckets found.")
    return public_buckets


find_public_buckets()
```

### 7. Find IAM Roles with Admin Access

**When they'd ask:** "What else in this account might be over-permissioned?"

```python
import boto3

iam = boto3.client('iam')

DANGEROUS_POLICIES = {
    'arn:aws:iam::aws:policy/AdministratorAccess',
    'arn:aws:iam::aws:policy/IAMFullAccess',
    'arn:aws:iam::aws:policy/PowerUserAccess',
}


def iter_policy_statements(doc):
    stmt = doc.get('Statement', [])
    return [stmt] if isinstance(stmt, dict) else stmt


def actions_include_star(action):
    if action == '*':
        return True
    if isinstance(action, list):
        return '*' in action
    return False


def find_overprivileged_roles():
    """Find roles with dangerous managed policies or wildcard inline policies."""
    findings = []
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            role_issues = []
            attached = iam.list_attached_role_policies(
                RoleName=role_name,
            )['AttachedPolicies']
            for p in attached:
                if p['PolicyArn'] in DANGEROUS_POLICIES:
                    role_issues.append(f"Managed: {p['PolicyName']}")
            for pol_name in iam.list_role_policies(RoleName=role_name)['PolicyNames']:
                doc = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=pol_name,
                )['PolicyDocument']
                for stmt in iter_policy_statements(doc):
                    if stmt.get('Effect') != 'Allow':
                        continue
                    if actions_include_star(stmt.get('Action', '')):
                        role_issues.append(f"Inline '{pol_name}': Action contains '*'")
            if role_issues:
                findings.append({'role': role_name, 'issues': role_issues})
                for issue in role_issues:
                    print(f"[OVERPRIVILEGED] {role_name}: {issue}")
    return findings


find_overprivileged_roles()
```

### 8. Enforce HTTPS on an S3 Bucket

**When they'd ask:** "How would you ensure this bucket only accepts encrypted connections?"

```python
import boto3
import json
from botocore.exceptions import ClientError

s3 = boto3.client('s3')


def iter_policy_statements(policy):
    stmt = policy.get('Statement', [])
    return [stmt] if isinstance(stmt, dict) else stmt


def enforce_https(bucket_name):
    """Deny S3 requests that do not use TLS (aws:SecureTransport)."""
    deny_http = {
        "Sid": "DenyInsecureTransport",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{bucket_name}",
            f"arn:aws:s3:::{bucket_name}/*",
        ],
        "Condition": {
            "Bool": {"aws:SecureTransport": "false"},
        },
    }
    try:
        existing = json.loads(s3.get_bucket_policy(Bucket=bucket_name)['Policy'])
    except ClientError as err:
        if err.response['Error']['Code'] == 'NoSuchBucketPolicy':
            existing = {"Version": "2012-10-17", "Statement": []}
        else:
            raise
    statements = iter_policy_statements(existing)
    if not any(s.get('Sid') == 'DenyInsecureTransport' for s in statements):
        statements.append(deny_http)
        existing['Statement'] = statements
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(existing))
        print(f"HTTPS enforced on {bucket_name}")
    else:
        print(f"HTTPS policy already exists on {bucket_name}")


enforce_https('my-sensitive-bucket')
```

---

## Prevention: Service Control Policies

SCPs are guardrails applied at the AWS Organization level. They don't grant permissions — they set the maximum boundary of what's allowed across all accounts in an OU. Even if an IAM admin in a department account attaches AdministratorAccess to a role, an SCP can block the dangerous action. This is the preventive control layer that stops the misconfigurations before they happen. In the interview, proposing SCPs in the "harden" step shows you think at the organizational level, not just per-account.

### SCP 1: Prevent Disabling GuardDuty

Prevents anyone in member accounts from disabling GuardDuty or deleting its detectors. Only the delegated admin in the security account should manage GuardDuty. (Intentionally omits `UpdateDetector` so the security team can tune detectors without a break-glass role.)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyGuardDutyDisable",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:StopMonitoringMembers",
        "guardduty:DisassociateMembers"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/SecurityAutomationRole"
        }
      }
    }
  ]
}
```

### SCP 2: Prevent Disabling CloudTrail

Prevents anyone from stopping CloudTrail logging, deleting trails, or tampering with the log bucket. Omits `PutEventSelectors` and `UpdateTrail` so the security team can enable data events and fix delivery without break-glass.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrailDisable",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/SecurityAutomationRole"
        }
      }
    },
    {
      "Sid": "ProtectCloudTrailBucket",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketPolicy"
      ],
      "Resource": "arn:aws:s3:::company-cloudtrail-logs*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/SecurityAutomationRole"
        }
      }
    }
  ]
}
```

### SCP 3: Block Overly Permissive Security Groups

Restricts who can **add** permissive SG rules (SCPs cannot inspect CIDR values). Revoke remains available to IR roles so teams can remove `0.0.0.0/0` during an incident. Pair with AWS Config rules `restricted-ssh` and `restricted-common-ports` for continuous detection.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictSGAuthorize",
      "Effect": "Deny",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": [
            "arn:aws:iam::*:role/NetworkAdminRole",
            "arn:aws:iam::*:role/InfrastructurePipelineRole"
          ]
        }
      }
    },
    {
      "Sid": "RestrictSGRevoke",
      "Effect": "Deny",
      "Action": [
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": [
            "arn:aws:iam::*:role/NetworkAdminRole",
            "arn:aws:iam::*:role/InfrastructurePipelineRole",
            "arn:aws:iam::*:role/IncidentResponseRole"
          ]
        }
      }
    }
  ]
}
```

### SCP 4: Enforce S3 Security Defaults

Three controls: block public access overrides, require encryption on upload (SSE-S3 or KMS), and prevent ACL usage.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyS3PublicAccessChange",
      "Effect": "Deny",
      "Action": "s3:PutAccountPublicAccessBlock",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/SecurityAutomationRole"
        }
      }
    },
    {
      "Sid": "DenyS3UploadWithoutEncryptionHeader",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyS3UploadWithWeakEncryption",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": [
            "aws:kms",
            "AES256"
          ]
        }
      }
    },
    {
      "Sid": "DenyS3ACLUsage",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketAcl",
        "s3:PutObjectAcl"
      ],
      "Resource": "*"
    }
  ]
}
```

### SCP 5: Enforce IAM Guardrails

Prevent the most dangerous IAM actions: block access key creation, require IMDSv2, and block attachment of high-risk managed policies.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAccessKeyCreation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateAccessKey"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": [
            "arn:aws:iam::*:role/SecurityAutomationRole",
            "arn:aws:iam::*:role/BreakGlassRole"
          ]
        }
      }
    },
    {
      "Sid": "RequireIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    },
    {
      "Sid": "DenyDangerousManagedPolicyAttach",
      "Effect": "Deny",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy"
      ],
      "Resource": "*",
      "Condition": {
        "ArnEquals": {
          "iam:PolicyArn": [
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:role/SecurityAutomationRole"
        }
      }
    }
  ]
}
```

### SCP 6: Restrict Insecure Connectivity

Restrict operations to approved regions and block accepting VPC peering from outside the organization. (Outbound peering requests to external VPCs still need Config/tag guardrails — SCPs cannot evaluate peer CIDRs on `CreateVpcPeeringConnection`.)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnapprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "sts:*",
        "organizations:*",
        "support:*",
        "cloudfront:*",
        "route53:*",
        "budgets:*",
        "waf:*",
        "wafv2:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-west-2",
            "us-east-1"
          ]
        }
      }
    },
    {
      "Sid": "DenyExternalVPCPeeringAccept",
      "Effect": "Deny",
      "Action": "ec2:AcceptVpcPeeringConnection",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:ResourceOrgID": "o-your-org-id-here"
        }
      }
    }
  ]
}
```

### How to Present SCPs in the Interview

When you reach the "harden" step of the incident walkthrough, say something like:

> "Beyond fixing this specific misconfiguration, I'd propose org-level SCPs so this class of issue can't recur in any account. For example, we'd deny StopLogging across all member accounts, require IMDSv2 on every EC2 launch, and block public S3 access overrides. These are guardrails that apply even if a department admin has full IAM permissions in their own account — the SCP is the ceiling they can't exceed."

This framing matters because it shows you're not just solving the incident — you're closing the gap for the whole org. It also connects naturally to the multi-department setup the recruiter described.

---

## Nintendo-Specific Angles

### Frame Answers for Their Environment

The scenario is *"a similar company to NOA, with multiple departments using AWS services to store and transform data, and customer-facing online web services."* Think: Nintendo Switch Online, eShop, game analytics pipelines, marketing sites.
- **Multi-department = multi-account:** Each department (game dev, online services, marketing, data analytics) likely has its own AWS account under an Organization. Your answers should assume cross-account visibility and centralized security tooling.
- **"Store and transform data":** S3 + Glue/Athena/EMR pipelines. Data security (encryption, access policies, data perimeters) is a first-class concern. Unreleased game assets in S3 are high-value targets.
- **"Customer-facing web services":** ALBs, EC2/ECS, API Gateway. Public-facing attack surface. Security group hygiene, WAF configuration, and DDoS protection (Shield) are relevant.
- **Wiz preference:** They use Wiz for CSPM. Wiz provides a graph-based view of attack paths — e.g., "this publicly exposed EC2 instance has a role that can read from an S3 bucket containing PII." If you've used Wiz, talk about the attack path visualization. If not, describe the concept and say you'd learn the specific tool quickly.
- **Your Sony experience:** Sony is another gaming/entertainment company with massive AWS footprint and similar security challenges. Draw direct parallels when answering — "at Sony, we handled multi-account security by..." This is your strongest differentiator.

### Questions to Ask Them

- "How many AWS accounts are you managing, and do you use a centralized security account for GuardDuty and Security Hub?"
- "What does your IR runbook process look like today — is it documented, or are you building it out?"
- "How do you handle security for game launch events when infrastructure scales rapidly?"
- "What's the split between proactive engineering (hardening, automation) and reactive work (incidents, tickets) in this role?"
- "How does the NOA security team coordinate with the global team in Kyoto?"

---

## Reference: The Capital One Breach

The canonical cloud security incident — good to reference if the scenario is similar.

- 2019. Attacker exploited SSRF vulnerability in a misconfigured ModSecurity WAF on EC2.
- Queried IMDSv1 (`169.254.169.254`) to get temp credentials for the `ISRM-WAF-Role`.
- That role had excessive permissions: `s3:ListBucket`, `s3:GetObject` on all buckets, plus `kms:Decrypt`.
- Exfiltrated 30 GB / 106M individuals' credit application data.

- **Every evaluation area failed:** IMDSv1 (no session tokens), overly permissive IAM role, no SG egress filtering, no S3 data event logging to catch the exfil in real-time, no outbound network segmentation, and CloudTrail analysis happened only after the breach was reported months later.
- **IMDSv2 would have blocked** the SSRF path: PUT request + headers are beyond most SSRF capabilities.