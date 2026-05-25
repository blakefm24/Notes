# Nintendo Cloud Security Engineer: Technical Prep

**Tuesday, May 26 (90 minutes) with the security engineering team.** This isn't a trivia quiz (or so they say :P). The format is a live incident scenario for a NOA-like company (multi-department AWS environment with customer-facing web services), with real GuardDuty/Wiz screenshots, working through triage, prioritization, and remediation out loud. CoderPad is included for live scripting demos: quick Python/Bash to solve a problem they surface, not a LeetCode exercise. The recruiter says the team keeps it light (top-tier memes); treat it as a working session, not a grilling. Prep below is organized around their six evaluation criteria.


| Detail              | Value                                 |
| ------------------- | ------------------------------------- |
| Interview Length    | 90 min with security engineering team |
| Core Format         | 1 incident, GuardDuty/Wiz triggered   |
| Scripting Demo      | CoderPad: Python/Bash expected        |
| Evaluation Criteria | 6 areas listed by recruiter           |


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
- [Wiz Security Graph: Parallel Queries](#wiz-security-graph-parallel-queries)
- [Log Analysis: Athena & Splunk](#log-analysis-athena--splunk)
- [Prevention: Service Control Policies](#prevention-service-control-policies)
- [Nintendo-Specific Angles](#nintendo-specific-angles)
- [Reference: The Capital One Breach](#reference-the-capital-one-breach)

---

## How to Approach the Live Incident

### Think Out Loud, in Layers

The evaluation targets thought process, not a rubric of AWS service names.

When incident screenshots are shown, use this mental model:

1. **Orient:** Read the GuardDuty/Wiz finding. State what type of alert it is (e.g., "This is a `Recon:EC2/PortProbeUnprotectedPort` finding: someone is probing an exposed port"). Ask clarifying questions about the environment: how many accounts, what services are in scope, what logging exists.
2. **Prioritize:** Assess severity. Is this active exploitation or a misconfiguration? What's the blast radius? Is sensitive data (customer PII, game IP) reachable from the affected resource? Name what to triage first and why.
3. **Contain:** Describe immediate actions: isolate the resource, revoke credentials, preserve evidence. Be specific about which AWS actions to take.
4. **Investigate:** Walk through the evidence chain: CloudTrail for API activity, VPC Flow Logs for network, S3 access logs for data exfil. Connect findings across the six evaluation areas.
5. **Remediate & Harden:** Fix the root cause, then propose preventive controls so it doesn't recur. This is where systems thinking shows. Draw from Sony incident experience when relevant. When asked how to handle the scenario, anchor in a real story: "At Sony, we had a similar situation where..." then map it to the scenario presented.

---

## 1. AWS GuardDuty

> **What They'll Evaluate (from recruiter):** Keeping agents/services enabled for threat detection. Gaps in monitoring coverage.

### Core Knowledge

- **What it analyzes:** CloudTrail management & data events, VPC Flow Logs, DNS query logs, EKS audit logs, S3 data events, Lambda network activity, and RDS login events. These are *protection plans* that can be individually enabled.
- **Common gap:** GuardDuty is enabled but S3 Protection or EKS Protection is off; the org thinks they're covered, but entire data planes are unmonitored. If an incident is shown and they ask "why didn't we catch this sooner," check which protection plans are active.
- **Finding types to know cold:**
  - `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`: EC2 role credentials used from outside AWS
  - `Recon:EC2/PortProbeUnprotectedPort`: open port being scanned
  - `Trojan:EC2/C&CActivity.B`: instance calling a C2 server
  - `Policy:S3/BucketPublicAccessGranted`: bucket made public
  - `Stealth:S3/ServerAccessLoggingDisabled`: logging turned off (covering tracks)
- **Multi-account:** Use delegated admin in AWS Organizations so GuardDuty findings aggregate to a central security account. If they have departments using separate AWS accounts, this is likely their setup.
- **Runtime Monitoring:** GuardDuty agent deployed to EC2/EKS/ECS for process-level visibility (file access, network connections, process execution). If not enabled, there is a blind spot between "API-level detection" and "what actually ran on the host."

### What to Say in the Interview

When the GuardDuty screenshot is shown, read the finding type, severity, affected resource, and actor. Then say something like: *"First question: is this finding from a protection plan that's actively monitored, or did we get lucky? I'd want to audit which GuardDuty features are enabled across all accounts to make sure we don't have coverage gaps."* This demonstrates thinking beyond the single alert.

---

## 2. AWS CloudTrail

> **What They'll Evaluate (from recruiter):** Enabling and retaining audit logs. Using logs for investigations, compliance, and incident response.

### Core Knowledge

- **Trail types:** Management events (API calls like `RunInstances`, `CreateBucket`) are enabled by default. Data events (S3 `GetObject`/`PutObject`, Lambda invocations) are *not*; these must be explicitly enabled and cost more, but they're critical for investigating data exfil.
- **Organization trail:** A single trail in the management account captures events from all member accounts. The incident scenario is multi-department, so expect this to be relevant.
- **Retention matters:** Default console view is 90 days. For compliance and IR, send events to an S3 bucket with lifecycle policies (keep 1+ year) and to CloudWatch Logs or a SIEM for real-time alerting. If they ask about compliance, mention that SOC 2 and PCI-DSS require durable audit logs.
- **Log integrity:** Enable CloudTrail log file validation (digest files) to prove logs haven't been tampered with. If an attacker disables CloudTrail (`StopLogging`), GuardDuty detects it as `Stealth:IAMUser/CloudTrailLoggingDisabled`.
- **Key fields for investigation:** `eventName`, `userIdentity` (who), `sourceIPAddress` (where), `requestParameters` (what), `eventTime` (when). Filter by access key ID to trace all actions from a specific credential.
- **Athena for querying:** Create an Athena table over CloudTrail logs in S3 to run SQL queries during an investigation. Fast for questions like "show me all S3 API calls from this IP in the last 72 hours." Sample queries: [Log Analysis: Athena & Splunk](#log-analysis-athena--splunk).

### CoderPad Angle

If scripting is requested, a CloudTrail log parser is likely. Something like: "Given these CloudTrail JSON events, find all API calls made by a specific access key ID after a given timestamp." This is straightforward Python: `json.load`, filter by `userIdentity.accessKeyId` and `eventTime`, print results.

---

## 3. Security Group Traffic

> **What They'll Evaluate (from recruiter):** Best practices for traffic rules. Risks of overly permissive rules. Principles of least privilege for network access. CIDR ranges and exposure risks.

### Core Knowledge

- **Security groups are stateful firewalls.** If inbound is allowed, the return traffic is automatically allowed. NACLs are stateless (both directions must be explicitly allowed).
- **The red flag:** Inbound rule with `0.0.0.0/0` on port 22 (SSH) or 3389 (RDP). This is the most common misconfiguration they'll test. In the incident scenario, an open port may be the entry point. Remote access via these ports should not be necessary in an AWS environment. In such a case, the customer should be guided to use AWS SSM instead (which is more secure and easier to audit). At SIE, we used what we called "bastion" hosts aka "jump hosts" and later moved to SSM.
- **Least privilege for SGs:** Reference other security groups instead of CIDR ranges when possible (e.g., "allow inbound 443 from the ALB security group" rather than a /16 block). Use specific CIDR ranges only for known external IPs (VPN, office).
- **CIDR risk assessment:** `/32` = single host (good). `/24` = 256 IPs. `/16` = 65K IPs. `/0` = the entire internet (almost never appropriate for inbound). Note that `0.0.0.0/0` is IPv4 "everywhere" and `::/0` is IPv6 "everywhere"; both must be locked down.
- **Outbound controls:** Default SG allows all outbound traffic. In a security-conscious environment, restrict outbound to necessary ports (443 for HTTPS, specific endpoints). This limits data exfil and C2 callbacks. If the incident involves an EC2 calling out to a malicious IP, unrestricted egress is the root cause.
- **Containment technique:** During an incident, swap the compromised instance's SG to a pre-staged "quarantine" group that denies all inbound/outbound. This isolates without terminating (preserves forensic evidence).

### CoderPad Angle

Possible scripting ask: "Write a script to find all security groups with inbound rules open to `0.0.0.0/0`." This is a boto3 one-liner pattern: `describe_security_groups`, iterate rules, check for `0.0.0.0/0` in `IpRanges`. Quick and clean.

---

## 4. AWS S3

> **What They'll Evaluate (from recruiter):** Securing S3 buckets/cloud storage. Read/write access across accounts. Encryption, access policies, and data exposure risks.

### Core Knowledge

- **Public access controls:** S3 Block Public Access settings exist at both the account level and bucket level. Account-level BPA should be on by default. If a bucket is public, it means someone deliberately (or accidentally) overrode it. Wiz flags this aggressively.
- **Bucket policies vs. ACLs:** Modern best practice is to disable ACLs entirely (bucket owner enforced) and use bucket policies for all access control. ACLs are legacy and hard to audit. If the scenario shows an ACL granting access, call it out as a misconfiguration.
- **Cross-account access:** In a multi-department setup, departments share S3 data via bucket policies with `Principal` set to a specific account/role ARN. The risk: overly broad principals (`"Principal": "*"` or `"Principal": {"AWS": "*"}`). Always scope to specific accounts, roles, and add `aws:PrincipalOrgID` conditions.
- **Encryption:** SSE-S3 (Amazon-managed keys) is the default since Jan 2023. SSE-KMS provides key management, audit trails via CloudTrail, and the ability to restrict decryption by IAM policy. For sensitive data, SSE-KMS with a customer-managed key (CMK) is the standard.
- **Data exfil detection:** Enable S3 server access logging or CloudTrail data events for S3. Look for unusual `GetObject` volume, access from unfamiliar IPs, or bulk downloads. GuardDuty's S3 protection detects anomalous access patterns.
- **VPC endpoints:** Use S3 gateway endpoints with endpoint policies to ensure buckets are only accessible from within the VPC, not over the public internet. This is a data perimeter control.

---

## 5. Identity & Access Management

> **What They'll Evaluate (from recruiter):** IAM role/policies and least privilege design. Attaching roles to compute resources/instances. Managed policies, like Systems Manager access.

### Core Knowledge

- **Roles on compute:** EC2 instances, Lambda functions, and ECS tasks should use IAM roles (via instance profiles or task roles), never long-lived access keys. The role provides short-term credentials from IMDS (EC2) or the container credential provider (ECS). If the incident involves static keys on an instance, flag it.
- **Systems Manager (SSM):** The recruiter called this out specifically. The `AmazonSSMManagedInstanceCore` managed policy allows SSM Agent to communicate with Systems Manager; this enables Session Manager access (replaces SSH), patch management, and inventory. The risk: this policy also allows `ssm:SendCommand` which can execute arbitrary commands on instances. Scope it tightly.
- **Least privilege design:** Start with zero permissions and add. Use IAM Access Analyzer to generate policies from CloudTrail activity. Scope resources to specific ARNs (not `*`). Add conditions: `aws:SourceVpc`, `aws:RequestedRegion`, `aws:PrincipalTag`.
- **Policy evaluation order:** Implicit deny → SCPs → Resource policies → Permission boundaries → Session policies → Identity policies. Explicit deny always wins.
- **Privilege escalation patterns:** `iam:PassRole` + compute creation (EC2/Lambda) is the most common. `iam:CreatePolicyVersion` with `--set-as-default` is the sneakiest. `iam:AttachRolePolicy` to grant AdministratorAccess is the loudest (easy to detect in CloudTrail).
- **Revoking active sessions:** Attach an inline deny-all policy with condition `aws:TokenIssueTime` before the current timestamp. All existing sessions are denied; new assumptions work normally.

### CoderPad Angle

Possible ask: "Find all IAM roles with AdministratorAccess attached" or "List all roles that haven't been used in 90 days." Both are `boto3` scripts: `list_roles()` → `list_attached_role_policies()`, or `get_role()` → check `RoleLastUsed`.

---

## 6. Secure Communication & Connectivity

> **What They'll Evaluate (from recruiter):** Proper use of secure ports/protocols like HTTPS. Controlling outbound access and restricting unnecessary connectivity.

### Core Knowledge

- **Enforce HTTPS everywhere:** Ensure S3 bucket policies include a `Deny` statement with condition `"aws:SecureTransport": "false"` to block HTTP. Redirect HTTP → HTTPS on ALBs and CloudFront. TLS 1.2+ minimum.
- **Outbound restriction:** Default security groups allow all egress. Lock egress down to only necessary destinations: port 443 for HTTPS to known endpoints, NTP (port 123), DNS (port 53). Use VPC endpoints for AWS services (S3, SSM, CloudWatch) to keep traffic off the public internet entirely.
- **Why outbound matters:** Unrestricted egress is how data gets exfiltrated and how compromised instances reach C2 servers. If the incident shows an EC2 instance calling out to an unknown IP on port 443, the question is "why was this allowed?" The answer: no egress filtering.
- **NAT Gateway vs. VPC Endpoints:** NAT Gateways route all outbound to the internet; traffic is visible in Flow Logs but destination cannot be restricted. VPC endpoints are direct, private connections to specific AWS services with their own access policies. Prefer endpoints for AWS API traffic.
- **SSH / RDP elimination:** Use SSM Session Manager instead of opening port 22/3389. Sessions are logged, auditable, and don't require inbound SG rules. This connects back to the SSM managed policy discussion in the IAM section.
- **Network segmentation:** In a multi-department company like the scenario describes, use separate VPCs or subnets per department with VPC peering or Transit Gateway. Security groups and NACLs enforce inter-department boundaries. Private subnets for compute, public subnets only for load balancers.

---

## Putting It Together: A Practice Incident

### Scenario: Wiz alerts on a public S3 bucket; GuardDuty flags credential exfiltration

Based on the recruiter's description, below is a plausible incident walkthrough that ties all six evaluation areas together. Practice narrating the response aloud.

- **Alert:** Wiz flags an S3 bucket in the data analytics department's account as publicly accessible. Minutes later, GuardDuty fires `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`: an EC2 role's credentials are being used from an external IP.
- **Triage (GuardDuty + S3):** Correlate the two alerts. The EC2 instance has an IAM role with broad S3 read access. The instance is in a public subnet with a security group allowing inbound `0.0.0.0/0` on port 80. Check: does it have IMDSv2 enforced? If `HttpTokens: optional`, an SSRF against the web app on port 80 could have harvested credentials from IMDSv1.
- **Contain (SG + IAM):** Swap the instance's security group to a quarantine SG (deny all in/out). Revoke the role's active sessions using a deny policy with `aws:TokenIssueTime` condition. Snapshot the EBS volume for forensics.
- **Investigate (CloudTrail):** Query CloudTrail for all API calls made by the compromised role's access key in the last 72 hours. Look for: `ListBuckets`, `GetObject` (data exfil), `CreateAccessKey` (persistence), any IAM modifications. Check VPC Flow Logs for the external IP that used the stolen credentials. See [Athena & Splunk queries](#log-analysis-athena--splunk).
- **Remediate (all six areas):**
  - **S3:** Enable account-level Block Public Access. Fix the bucket policy. Enable SSE-KMS.
  - **IAM:** Scope the role to specific bucket ARNs. Remove `s3:`* and replace with `s3:GetObject` on necessary resources only.
  - **SG:** Remove `0.0.0.0/0` inbound. Move the instance to a private subnet behind an ALB.
  - **IMDS:** Enforce IMDSv2 (`HttpTokens=required`) on all instances via launch templates.
  - **Connectivity:** Add an S3 VPC endpoint with an endpoint policy scoped to the necessary buckets. Restrict egress in the SG.
  - **CloudTrail:** Ensure S3 data events are enabled for sensitive buckets. Verify log retention is at least 1 year.
  - **GuardDuty:** Confirm S3 Protection and Runtime Monitoring are enabled across all accounts.

---

## CoderPad: Python Snippets

The CoderPad is for demonstrating how to automate a response or audit, not a LeetCode test. Write clean, readable code. The focus is knowing the right boto3 calls and structuring a script logically. Keep these patterns in mind; adapt them to whatever the scenario asks for. Each snippet includes a **How it works** footnote below the code; use these to explain the approach, the key API calls, and any caveats the interviewer might probe on.

For the same audits in steady-state operations, Wiz Security Graph queries (see [Wiz Security Graph: Parallel Queries](#wiz-security-graph-parallel-queries)) are the preferred path; the boto3 scripts remain the IR and CoderPad complement. For full-fidelity investigation over retained logs, pivot to [Athena & Splunk](#log-analysis-athena--splunk).

### 1. Find Security Groups Open to the Internet

**Likely prompt:** The incident involves an exposed instance. "Can you write something to find all other groups with the same problem?"

```python
import boto3

# Run per region (or loop regions) for org-wide coverage
ec2 = boto3.client('ec2')

INTERNET_CIDRS_V4 = ('0.0.0.0/0',)
INTERNET_CIDRS_V6 = ('::/0',)


def _open_internet_cidrs(rule):
    """Return any internet-wide CIDRs on a single SG rule."""
    open_v4 = [
        r['CidrIp'] for r in rule['IpRanges']
        if r['CidrIp'] in INTERNET_CIDRS_V4
    ] if 'IpRanges' in rule else []
    open_v6 = [
        r['CidrIpv6'] for r in rule['Ipv6Ranges']
        if r['CidrIpv6'] in INTERNET_CIDRS_V6
    ] if 'Ipv6Ranges' in rule else []
    return open_v4 + open_v6


def find_open_security_groups():
    """Find SG rules allowing inbound or outbound access from the internet."""
    findings = []
    paginator = ec2.get_paginator('describe_security_groups')
    for page in paginator.paginate():
        for sg in page['SecurityGroups']:
            # Check inbound (IpPermissions) and outbound (IpPermissionsEgress)
            for direction, rules in (
                ('inbound', sg['IpPermissions']),
                ('outbound', sg['IpPermissionsEgress']),
            ):
                for rule in rules:
                    open_cidrs = _open_internet_cidrs(rule)
                    if open_cidrs:
                        findings.append({
                            'sg_id': sg['GroupId'],
                            'sg_name': sg['GroupName'],
                            'direction': direction,
                            'port': rule['FromPort'] if 'FromPort' in rule else 'all',
                            'protocol': rule['IpProtocol'] if 'IpProtocol' in rule else 'all',
                            'open_to': open_cidrs,
                        })
    for f in findings:
        print(f"[OPEN] {f['sg_id']} ({f['sg_name']}) {f['direction']} "
              f"port {f['port']} -> {f['open_to']}")
    return findings


find_open_security_groups()
```

**How it works:** The script paginates through every security group in the region via `describe_security_groups`, then inspects both inbound (`IpPermissions`) and outbound (`IpPermissionsEgress`) rule sets. A helper function scans each rule's IPv4 and IPv6 CIDR blocks for `0.0.0.0/0` or `::/0`; when found, the finding records the group ID, direction, port, protocol, and the open CIDRs. Pagination handles accounts with large SG inventories; checking both directions catches outbound exfil paths, not just inbound exposure. In the interview, note that org-wide coverage requires looping regions (or using Security Hub / Config aggregators).

### 2. Find EC2 Instances Still on IMDSv1

**Likely prompt:** After discovering SSRF or credential theft via metadata. "How would you audit the rest of the fleet?"

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
                md = inst['MetadataOptions']
                # IMDS disabled; not reachable, not in scope for SSRF cred theft
                if md['HttpEndpoint'] == 'disabled':
                    continue
                if md['HttpTokens'] != 'required':
                    tags = inst['Tags'] if 'Tags' in inst else []
                    name = next(
                        (t['Value'] for t in tags if t['Key'] == 'Name'),
                        'unnamed',
                    )
                    entry = {
                        'instance_id': inst['InstanceId'],
                        'name': name,
                        'http_tokens': md['HttpTokens'] if 'HttpTokens' in md else 'unknown',
                        'http_endpoint': md['HttpEndpoint'] if 'HttpEndpoint' in md else 'unknown',
                        'hop_limit': md['HttpPutResponseHopLimit'] if 'HttpPutResponseHopLimit' in md else None,
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

**How it works:** The script walks the fleet with paginated `describe_instances`, skipping instances in terminal states. For each running instance, it reads `MetadataOptions` and flags any instance where `HttpTokens` is not set to `required` (meaning IMDSv1 is still permitted). Instances with `HttpEndpoint` disabled are excluded because the metadata service is unreachable and not exploitable via SSRF. The output includes the hop limit (`HttpPutResponseHopLimit`), which matters in container and SSRF scenarios where a hop limit of 1 can block lateral metadata access. Remediation is enforced via launch templates or an account-level default requiring IMDSv2.

### 3. Quarantine a Compromised Instance

**Likely prompt:** "Show me how you'd contain this." This is a high-impact script, as it maps directly to the incident flow.

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
    # Instance store volumes are not captured; note that in the interview.
    for bdm in instance['BlockDeviceMappings']:
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

    # STEP 2: Network isolation: swap to quarantine SG (no in/out).
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg_id],
    )
    print(f"Swapped SGs to quarantine: {quarantine_sg_id}")

    # STEP 3: Tag for coordination (truncate SG list; tag value max 256 chars).
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

**How it works:** Containment follows a three-step IR playbook: preserve evidence, isolate network, document state. First, `describe_instances` retrieves the instance's current security groups and EBS volume mappings; `create_snapshot` captures each EBS volume with IR tags before any network changes (instance store volumes are not captured... call that out in the interview). Second, `modify_instance_attribute` replaces all attached security groups with a pre-provisioned quarantine SG that denies all inbound and outbound traffic. Third, `create_tags` marks the instance with quarantine metadata and preserves the original SG list for rollback. The quarantine SG must exist before running the script; it is a deny-all group created out of band.

### 4. Investigate CloudTrail for a Compromised Access Key

**Likely prompt:** "We have the access key ID from the GuardDuty finding. What did the attacker do with it?"

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
        name = e['EventName']
        if name not in api_calls:
            api_calls[name] = 0
        api_calls[name] += 1

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
        print(f"\n[WARN] HIGH-RISK API calls detected: {found_risky}")
    return events


# GuardDuty credential exfil often surfaces a session key (ASIA...), not AKIA...
investigate_access_key('ASIA1234567890EXAMPLE')
```

**How it works:** Triage starts with `lookup_events`, filtered by `AccessKeyId` and a configurable time window (default 72 hours). Results are paginated and aggregated by `EventName` to produce a quick picture of attacker activity. A predefined set of high-risk API calls (privilege escalation, persistence, log tampering) is intersected with the observed calls to surface immediate threats. `lookup_events` is suitable for initial triage but is subject to API limits and retention caps (~90 days); for a full investigation, pivot to CloudTrail Lake or Athena queries against the org trail in S3. GuardDuty credential exfil findings often surface session keys (`ASIA...`) rather than long-term keys (`AKIA...`); both work as lookup attributes.

### 5. Re-Enable CloudTrail Logging

**Likely prompt:** GuardDuty fires `Stealth:IAMUser/CloudTrailLoggingDisabled`: an attacker (or misconfiguration) stopped logging to cover tracks. "How would you find and fix all disabled trails?"

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
        home_region = trail['HomeRegion'] if 'HomeRegion' in trail else 'unknown'
        # API expects trail name, not ARN
        status = ct.get_trail_status(Name=trail_name)
        if not status['IsLogging']:
            print(f"[STOPPED] {trail_name} ({trail_arn}) region={home_region}")
            stop_time = status['LatestDeliveryTime'] if 'LatestDeliveryTime' in status else 'unknown'
            print(f"  Last delivery: {stop_time}")
            ct.start_logging(Name=trail_name)
            verify = ct.get_trail_status(Name=trail_name)
            if verify['IsLogging']:
                print("  [OK] Logging re-enabled and confirmed")
                fixed.append({
                    'trail': trail_name,
                    'arn': trail_arn,
                    'last_delivery': str(stop_time),
                })
            else:
                print("  [FAIL] Failed to re-enable; investigate manually")
        else:
            print(f"[OK] {trail_name}: logging active")

    print(f"\nResults: {len(fixed)} trail(s) re-enabled out of {len(trails)} total")
    if fixed:
        print("\nNext steps:")
        print("  1. Query CloudTrail for StopLogging: identify who disabled logging")
        print("  2. Verify log file validation (digest files) is enabled")
        print("  3. Confirm the log delivery S3 bucket exists and is accessible")
        print("  4. Assess log gaps during the disabled window (Athena/Lake)")
    return fixed


reenable_cloudtrail_logging()
```

**How it works:** The script lists all trails in the region with `describe_trails`, then checks each trail's logging state via `get_trail_status` (note: the API expects the trail name, not the ARN). Trails where `IsLogging` is false are re-enabled with `start_logging`, and a second status check confirms the fix. Stopped trails are a common attacker tactic after initial access (GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled`); re-enabling logging is the immediate remediation, but the investigation is not done. Post-fix steps include querying CloudTrail for `StopLogging` events to identify who disabled logging, verifying log file validation (digest files) is enabled, confirming the delivery S3 bucket is intact, and assessing log gaps during the disabled window via Athena or CloudTrail Lake.

### 6. Find Public S3 Buckets

**Likely prompt:** "The incident started with an exposed bucket. How many others are at risk?"

```python
import boto3
import json
from botocore.exceptions import ClientError

s3_global = boto3.client('s3')


def bucket_region(bucket_name):
    resp = s3_global.get_bucket_location(Bucket=bucket_name)
    loc = resp['LocationConstraint'] if 'LocationConstraint' in resp else None
    return loc or 'us-east-1'


def iter_policy_statements(policy):
    stmt = policy['Statement']
    return [stmt] if isinstance(stmt, dict) else stmt


def is_public_principal(principal):
    if principal == '*':
        return True
    if isinstance(principal, dict):
        aws = principal['AWS'] if 'AWS' in principal else None
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
                config['BlockPublicAcls'],
                config['IgnorePublicAcls'],
                config['BlockPublicPolicy'],
                config['RestrictPublicBuckets'],
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
                if stmt['Effect'] == 'Allow' and is_public_principal(stmt['Principal']):
                    issues.append(f"Policy allows public access: {stmt['Action']}")
        except ClientError as err:
            if err.response['Error']['Code'] != 'NoSuchBucketPolicy':
                issues.append(f'Policy read error: {err.response["Error"]["Code"]}')
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                grantee = grant['Grantee']
                uri = grantee['URI'] if 'URI' in grantee else ''
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

**How it works:** Each bucket is evaluated against three independent exposure vectors. First, Block Public Access (BPA): all four settings (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) must be true; a missing BPA configuration is itself a finding. Second, the bucket policy: statements with `Effect: Allow` and a public principal (`*` or `Principal:` *) are flagged. Third, the bucket ACL: grants to `AllUsers` (anonymous) or `AuthenticatedUsers` (any AWS account) are flagged. A regional S3 client is created per bucket because `list_buckets` is global but policy and ACL APIs are regional. `ClientError` handling distinguishes "no policy" (expected) from permission errors. Public exposure can exist at any layer even when others are locked down; checking all three reflects defense-in-depth understanding.

### 7. Find IAM Roles with Admin Access

**Likely prompt:** "What else in this account might be over-permissioned?"

```python
import boto3

iam = boto3.client('iam')

DANGEROUS_POLICIES = {
    'arn:aws:iam::aws:policy/AdministratorAccess',
    'arn:aws:iam::aws:policy/IAMFullAccess',
    'arn:aws:iam::aws:policy/PowerUserAccess',
}


def iter_policy_statements(doc):
    stmt = doc['Statement']
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
                    if stmt['Effect'] != 'Allow':
                        continue
                    action = stmt['Action'] if 'Action' in stmt else ''
                    if actions_include_star(action):
                        role_issues.append(f"Inline '{pol_name}': Action contains '*'")
            if role_issues:
                findings.append({'role': role_name, 'issues': role_issues})
                for issue in role_issues:
                    print(f"[OVERPRIVILEGED] {role_name}: {issue}")
    return findings


find_overprivileged_roles()
```

**How it works:** The script paginates through all IAM roles and checks two permission sources. Attached managed policies are compared against a set of known high-privilege AWS managed policy ARNs (`AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess`). Inline policies are fetched individually and parsed for `Action:` * or `Action: ["...", "*"]` in Allow statements, which grant unrestricted access within the policy's resource scope. A helper normalizes policy documents where `Statement` may be a single object or a list (common in both IAM and S3 policy formats). This audit identifies lateral movement targets after compromise; in the interview, pair findings with remediation paths (scoped custom policies, permission boundaries, SCPs to cap maximum permissions).

### 8. Enforce HTTPS on an S3 Bucket

**Likely prompt:** "How would you ensure this bucket only accepts encrypted connections?"

```python
import boto3
import json
from botocore.exceptions import ClientError

s3 = boto3.client('s3')


def iter_policy_statements(policy):
    stmt = policy['Statement']
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
    if not any(s['Sid'] == 'DenyInsecureTransport' for s in statements if 'Sid' in s):
        statements.append(deny_http)
        existing['Statement'] = statements
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(existing))
        print(f"HTTPS enforced on {bucket_name}")
    else:
        print(f"HTTPS policy already exists on {bucket_name}")


enforce_https('my-sensitive-bucket')
```

**How it works:** The script adds a bucket policy `Deny` statement conditioned on `aws:SecureTransport: false`, which blocks any request not made over TLS regardless of what Allow statements exist elsewhere in the policy (explicit deny wins in AWS policy evaluation). The existing bucket policy is fetched and parsed first; if no policy exists, a new document is created rather than overwriting unrelated configuration. The check for an existing `DenyInsecureTransport` Sid makes the operation idempotent. The deny applies to both the bucket and object ARNs (`bucket/`*). In the interview, note this is a data-at-rest/in-transit control at the bucket layer; it complements (but does not replace) encryption settings and CloudFront/ALB HTTPS termination upstream.

---

## Wiz Security Graph: Parallel Queries

Wiz answers the same audit questions as the boto3 snippets through the **Security Graph** (relationship-aware search), **Issues / Configuration Findings** (continuous posture rules), and **Attack Paths** (toxic combinations). Exact WQL field names can vary by tenant and graph version; validate queries in **Explore > Security Graph** or the query builder, and use **Ask AI** to translate natural language when syntax is uncertain.

### How to use this section in the interview


| Moment                   | Lead with                                                                   |
| ------------------------ | --------------------------------------------------------------------------- |
| Steady-state / posture   | Wiz Issues or Graph search (continuous, prioritized, attack-path context)   |
| Active IR / CoderPad ask | boto3 (immediate, account-local, chains into containment)                   |
| Showing Wiz depth        | One natural-language graph query + one attack-path example for the scenario |


**Framing line:** "Day to day, Wiz owns detection and prioritization on the graph; during an incident I'd still hit IAM and EC2 APIs directly to contain and verify scope before the dashboard catches up."

### Query surfaces (three ways to get the same answer)

1. **Security Graph search (WQL):** Text or JSON graph queries over entities and relationships (`FIND` / `WHERE`, `path_to`, `reachable_from`).
2. **Issues > Filter:** Search open Issues by resource type, rule name, or severity (maps to built-in cloud configuration rules).
3. **Inventory > Resource page:** Pivot from a known resource (e.g. the bucket from the Wiz alert screenshot) to related risks and attack paths.

---

### 1. Security groups open to the internet

**Python snippet:** [Find Security Groups Open to the Internet](#1-find-security-groups-open-to-the-internet)

**Natural language (Ask AI / search bar):**

- Security groups with inbound or outbound rules allowing `0.0.0.0/0` or `::/0`
- Internet-exposed security group rules on SSH, RDP, or all ports

**Security Graph (text-style WQL):**

```
FIND network_security_group
WHERE rule allows cidr "0.0.0.0/0" OR rule allows cidr "::/0"
```

```
FIND virtual_machine
WHERE exposed_to = "internet"
AND uses network_security_group with rule allowing "0.0.0.0/0"
```

**Issues shortcut:** Filter Issues for rules such as "Security group allows ingress from 0.0.0.0/0" or "Unrestricted inbound access" (exact rule title varies by Wiz rule set).

**Depth probe:** Wiz also shows **which workloads** attach to the open SG; boto3 lists rules only. Mention prioritizing SGs attached to internet-facing ENIs.

---

### 2. EC2 instances still on IMDSv1

**Python snippet:** [Find EC2 Instances Still on IMDSv1](#2-find-ec2-instances-still-on-imdsv1)

**Natural language:**

- EC2 instances that do not require IMDSv2
- Virtual machines with IMDSv1 enabled or `HttpTokens` optional

**Security Graph (text-style WQL):**

```
FIND virtual_machine
WHERE cloud_platform = "AWS"
AND imds_v2_required = false
AND imds_endpoint != "disabled"
```

**Issues shortcut:** Configuration finding for IMDSv1 allowed / IMDSv2 not required on EC2.

**Depth probe:** Tie to Capital One: public-facing VM + IMDSv1 + overprivileged instance role + reachable sensitive datastore = critical attack path in Wiz.

---

### 3. Quarantine a compromised instance

**Python snippet:** [Quarantine a Compromised Instance](#3-quarantine-a-compromised-instance)

Wiz does not execute containment; it **identifies** the instance and context for the quarantine decision.

**Natural language:**

- EC2 instances with GuardDuty credential exfiltration or instance credential exfiltration outside AWS
- Internet-exposed virtual machines with high-severity detections

**Security Graph (attack path):**

```
FIND virtual_machine
WHERE exposed_to = "internet"
AND has_detection type "CredentialAccess"
```

```
FIND virtual_machine
WHERE exposed_to = "internet"
AND can_access datastore
AND has_detection severity >= "HIGH"
```

**Issues / Defend:** Runtime or cloud event Issues linked to the instance; pivot to attached IAM role and reachable S3 buckets from the resource page.

**Depth probe:** "Wiz tells me *what* to isolate and *why*; boto3 snapshots and swaps the SG because Wiz cannot replace IR playbooks."

---

### 4. Investigate CloudTrail for a compromised access key

**Python snippet:** [Investigate CloudTrail for a Compromised Access Key](#4-investigate-cloudtrail-for-a-compromised-access-key)

Wiz correlates identity risk; **API-level history** for a specific key is still CloudTrail (or Wiz's CloudTrail ingestion if enabled).

**Natural language:**

- IAM identity or access key with anomalous API activity
- Identities that performed privilege escalation or created access keys

**Security Graph (identity / CIEM):**

```
FIND identity
WHERE access_key_id = "ASIA1234567890EXAMPLE"
```

```
FIND identity
WHERE performed_action IN ("CreateAccessKey", "AttachUserPolicy", "PutRolePolicy", "RunInstances")
AND last_active within 72 hours
```

**Issues shortcut:** High-risk IAM activity Issues; pivot to CloudTrail event timeline on the identity object if integrated.

**Depth probe:** "For pad-level triage I'd use `lookup_events`; for org-wide hunting I'd use [Athena or Splunk](#1-api-activity-for-a-compromised-access-key) on the trail bucket, or Wiz if CloudTrail is connected to the graph."

---

### 5. CloudTrail logging disabled

**Python snippet:** [Re-Enable CloudTrail Logging](#5-re-enable-cloudtrail-logging)

**Natural language:**

- CloudTrail trails with logging stopped
- Accounts where CloudTrail is not logging management events

**Security Graph (text-style WQL):**

```
FIND cloud_account
WHERE cloudtrail_logging_enabled = false
```

```
FIND cloud_resource
WHERE type = "CloudTrail"
AND is_logging = false
```

**Issues shortcut:** Search Issues for "CloudTrail logging disabled" or `StopLogging`-related configuration findings.

**Depth probe:** Pair with GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` and post-fix CloudTrail query for who called `StopLogging`.

---

### 6. Public S3 buckets

**Python snippet:** [Find Public S3 Buckets](#6-find-public-s3-buckets)

**Natural language:**

- Publicly accessible S3 buckets
- S3 buckets with public ACL, public policy, or Block Public Access not fully enabled

**Security Graph (text-style WQL):**

```
FIND datastore
WHERE type = "S3"
AND public = true
```

```
FIND datastore
WHERE type = "S3"
AND public = true
AND classification IN ("PII", "PCI", "PHI", "Sensitive")
```

```
FIND datastore
WHERE public = true OR encryption = disabled
```

**Issues shortcut:** Filter Issues for S3 public access / Block Public Access / anonymous ACL or policy findings (matches the Wiz alert in the practice incident).

**Depth probe:** Wiz adds **data classification** and **attack paths** (public bucket + identity that can reach it); boto3 checks BPA, policy, and ACL mechanically.

---

### 7. IAM roles with admin access

**Python snippet:** [Find IAM Roles with Admin Access](#7-find-iam-roles-with-admin-access)

**Natural language:**

- IAM roles with AdministratorAccess or IAMFullAccess
- Overprivileged service accounts and roles with wildcard Actions

**Security Graph (CIEM / text-style WQL):**

```
FIND identity
WHERE type = "IAM_ROLE"
AND has_policy "AdministratorAccess"
```

```
FIND identity
WHERE effective_permissions contains "*"
AND type = "IAM_ROLE"
```

```
FIND identity
WHERE attached_policy_arn CONTAINS "AdministratorAccess"
   OR attached_policy_arn CONTAINS "IAMFullAccess"
   OR attached_policy_arn CONTAINS "PowerUserAccess"
```

**Issues shortcut:** CIEM / "Overly permissive role" / "Admin privileges" configuration or Issues views.

**Depth probe:** Wiz CIEM shows **effective permissions** and **unused access**; boto3 only checks attached ARNs and inline `Action:` *.

---

### 8. S3 buckets without HTTPS enforced

**Python snippet:** [Enforce HTTPS on an S3 Bucket](#8-enforce-https-on-an-s3-bucket)

**Natural language:**

- S3 buckets without a deny-insecure-transport bucket policy
- Datastores allowing HTTP access (`aws:SecureTransport` not enforced)

**Security Graph (text-style WQL):**

```
FIND datastore
WHERE type = "S3"
AND secure_transport_enforced = false
```

**Issues shortcut:** Configuration finding for missing `aws:SecureTransport` deny or allow-insecure transport.

**Depth probe:** Bucket policy deny is one layer; also mention ALB/CloudFront TLS and SCP `Deny` on unencrypted `PutObject` (see [SCP 4](#scp-4-enforce-s3-security-defaults)).

---

### Practice incident: attack-path query (ties the scenario together)

Use when the Wiz screenshot shows a **public bucket + credential exfil** chain:

**Natural language:**

- Internet-exposed EC2 with access to a public S3 bucket containing sensitive data
- Attack path from internet to S3 with instance credentials

**Security Graph (text-style WQL):**

```
FIND virtual_machine
WHERE exposed_to = "internet"
AND path_to(datastore WHERE type = "S3" AND public = true)
```

```
FIND virtual_machine
WHERE exposed_to = "internet"
AND has_secret = true
AND path_to(datastore WHERE classification IN ("PII", "Sensitive"))
```

**What this demonstrates:** Wiz value is not replacing boto3; it is **prioritizing** which open SG, IMDSv1 instance, and public bucket matter because they connect on the graph.

---

### JSON graph queries (optional depth)

The Wiz UI and API often represent graph searches as JSON (example from Wiz engineering blog: VMs with unencrypted volumes):

```json
{
  "type": ["VIRTUAL_MACHINE"],
  "relationships": [{
    "type": [{"type": "USES"}],
    "with": {
      "type": ["VOLUME"],
      "where": { "encrypted": { "EQUALS": false } }
    }
  }]
}
```

If asked how Wiz works under the hood: natural language and text queries compile to graph JSON over entities (`VIRTUAL_MACHINE`, `DATASTORE`, `IDENTITY`, etc.) and relationships (`USES`, `CAN_ACCESS`, `EXPOSED_TO`). Exact schema is tenant-specific; **Ask AI** and the query builder are the source of truth.

---

### Quick reference: boto3 vs Wiz


| Audit               | boto3 (IR / CoderPad)                       | Wiz (steady-state)                   |
| ------------------- | ------------------------------------------- | ------------------------------------ |
| Open SGs            | `describe_security_groups`                  | Graph: open CIDR rules; Issues       |
| IMDSv1              | `describe_instances` + `MetadataOptions`    | Config finding + attack path         |
| Quarantine          | snapshot, `modify_instance_attribute`, tags | Findings + blast radius on graph     |
| Access key activity | `lookup_events` / Athena                    | Identity risk + detections           |
| Trail stopped       | `get_trail_status`, `start_logging`         | Config finding + Stealth correlation |
| Public S3           | BPA + policy + ACL APIs                     | `FIND datastore ... public = true`   |
| Admin roles         | `list_roles` + policy APIs                  | CIEM / overprivileged identity       |
| HTTPS on S3         | merge bucket policy                         | Config finding + policy gap          |


CloudTrail and VPC Flow Log hunts: [Log Analysis: Athena & Splunk](#log-analysis-athena--splunk).

---

## Log Analysis: Athena & Splunk

CloudTrail answers **who did what API call, when, and from where**. VPC Flow Logs answer **which IPs talked to which ENIs on which ports** (metadata only; no payload). In the practice incident, both tie together: CloudTrail shows `GetObject` and `StopLogging`; flow logs show the external IP using stolen credentials or calling out to C2.

**Investigation ladder:**

1. **Fast triage:** `lookup_events` (boto3) or SIEM alert pivot
2. **Deep hunt:** Athena (org trail in S3) or Splunk over forwarded logs
3. **Network corroboration:** VPC Flow Logs in Athena or Splunk (`vpc_flow_logs` index)

Replace placeholders before running: `ASIA...`, `10.0.1.50`, `eni-...`, date partitions, index names.

### Prerequisites (say out loud if asked)


| Source        | Athena                                                                                          | Splunk                                                                                      |
| ------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| CloudTrail    | Table over S3 delivery bucket (e.g. `cloudtrail_logs`), or **CloudTrail Lake** event data store | Index/sourcetype from Splunk Add-on for AWS (e.g. `index=aws_ct sourcetype=aws:cloudtrail`) |
| VPC Flow Logs | Table over flow log S3 prefix (e.g. `vpc_flow_logs`)                                            | Index (e.g. `index=aws_vpcflow sourcetype=aws:vpcflow`)                                     |
| Partitions    | `year` / `month` / `day` on CloudTrail; `date` on flow logs                                     | `earliest` / `latest` in search time range                                                  |


**CloudTrail key fields:** `eventname`, `eventtime`, `sourceipaddress`, `useridentity.accesskeyid`, `useridentity.arn`, `useridentity.type`, `requestparameters`, `errorcode`

**VPC Flow Log key fields:** `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `action` (`ACCEPT` / `REJECT`), `interface_id`, `bytes`

**Framing line:** "`lookup_events` is enough to orient; Athena or Splunk is how the team proves scope, finds log gaps, and builds the timeline for leadership."

---

### 1. API activity for a compromised access key

**Maps to:** [Investigate CloudTrail for a Compromised Access Key](#4-investigate-cloudtrail-for-a-compromised-access-key), practice incident credential exfil.

**Athena (CloudTrail on S3):**

```sql
-- API call summary for a session or long-term key (last 72 hours)
SELECT
  eventname,
  COUNT(*) AS event_count,
  MIN(eventtime) AS first_seen,
  MAX(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'ASIA1234567890EXAMPLE'
  AND eventtime >= current_timestamp - interval '72' hour
  AND year = '2026' AND month = '05'  -- align to partition columns
GROUP BY eventname
ORDER BY event_count DESC;
```

```sql
-- Detailed timeline with source IP and user agent
SELECT
  eventtime,
  eventname,
  sourceipaddress,
  useridentity.arn,
  useridentity.type,
  useragent,
  errorcode
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'ASIA1234567890EXAMPLE'
  AND eventtime >= current_timestamp - interval '72' hour
ORDER BY eventtime ASC;
```

**Splunk:**

```spl
index=aws_ct UserIdentity.AccessKeyId="ASIA1234567890EXAMPLE" earliest=-72h@h
| stats count as event_count earliest(_time) as first_seen latest(_time) as last_seen by EventName
| sort - event_count
```

```spl
index=aws_ct UserIdentity.AccessKeyId="ASIA1234567890EXAMPLE" earliest=-72h@h
| table _time EventName SourceIpAddress UserIdentity.Arn UserAgent ErrorCode
| sort _time
```

**Depth probe:** Session keys (`ASIA`) include `useridentity.sessioncontext`; long-term keys (`AKIA`) map to IAM users. Data events (`GetObject`) require data event logging or Lake; management trail alone may miss object reads.

---

### 2. High-risk / persistence API calls

**Maps to:** risky set in Python snippet; IAM persistence in practice incident.

**Athena:**

```sql
SELECT
  eventtime,
  eventname,
  useridentity.arn,
  sourceipaddress,
  requestparameters
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'ASIA1234567890EXAMPLE'
  AND eventname IN (
    'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy',
    'PutUserPolicy', 'PutRolePolicy', 'CreatePolicyVersion',
    'RunInstances', 'CreateLoginProfile', 'UpdateAssumeRolePolicy',
    'AddUserToGroup', 'CreateUser',
    'StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutBucketPolicy'
  )
  AND eventtime >= current_timestamp - interval '72' hour
ORDER BY eventtime;
```

**Splunk:**

```spl
index=aws_ct UserIdentity.AccessKeyId="ASIA1234567890EXAMPLE" earliest=-72h@h
  (EventName=CreateAccessKey OR EventName=AttachUserPolicy OR EventName=AttachRolePolicy
   OR EventName=PutUserPolicy OR EventName=PutRolePolicy OR EventName=CreatePolicyVersion
   OR EventName=RunInstances OR EventName=CreateLoginProfile OR EventName=UpdateAssumeRolePolicy
   OR EventName=AddUserToGroup OR EventName=CreateUser
   OR EventName=StopLogging OR EventName=DeleteTrail OR EventName=UpdateTrail OR EventName=PutBucketPolicy)
| table _time EventName UserIdentity.Arn SourceIpAddress requestParameters
| sort _time
```

---

### 3. S3 data exfiltration (`GetObject` / `ListBucket`)

**Maps to:** practice incident S3 read access via compromised role.

**Athena (requires S3 data events in trail or Lake):**

```sql
SELECT
  eventtime,
  eventname,
  useridentity.accesskeyid,
  sourceipaddress,
  json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
  json_extract_scalar(requestparameters, '$.key') AS object_key,
  errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject', 'ListBucket', 'ListObjectsV2')
  AND useridentity.accesskeyid = 'ASIA1234567890EXAMPLE'
  AND eventtime >= current_timestamp - interval '72' hour
ORDER BY eventtime;
```

**Splunk:**

```spl
index=aws_ct eventSource=s3.amazonaws.com
  (EventName=GetObject OR EventName=ListBucket OR EventName=ListObjectsV2)
  UserIdentity.AccessKeyId="ASIA1234567890EXAMPLE" earliest=-72h@h
| eval bucket=coalesce(requestParameters.bucketName, requestParameters.bucket)
| table _time EventName SourceIpAddress bucket requestParameters.key
| sort _time
```

**Depth probe:** If zero rows, state that data events were likely not enabled; recommend enabling on sensitive buckets and re-running for future incidents.

---

### 4. CloudTrail tampering (`StopLogging` / `DeleteTrail`)

**Maps to:** [Re-Enable CloudTrail Logging](#5-re-enable-cloudtrail-logging), GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled`.

**Athena:**

```sql
-- Who disabled logging and when (org-wide hunt)
SELECT
  eventtime,
  eventname,
  useridentity.arn,
  useridentity.type,
  sourceipaddress,
  requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
  AND eventsource = 'cloudtrail.amazonaws.com'
  AND eventtime >= current_timestamp - interval '7' day
ORDER BY eventtime DESC;
```

```sql
-- Assess logging gap: last event before StopLogging vs first after StartLogging
SELECT eventname, eventtime, useridentity.arn
FROM cloudtrail_logs
WHERE requestparameters LIKE '%trail-name%'
  AND eventname IN ('StopLogging', 'StartLogging')
  AND eventtime >= current_timestamp - interval '7' day
ORDER BY eventtime;
```

**Splunk:**

```spl
index=aws_ct EventName=StopLogging OR EventName=DeleteTrail OR EventName=UpdateTrail earliest=-7d@d
| table _time EventName UserIdentity.Arn SourceIpAddress requestParameters
| sort - _time
```

**Depth probe:** Cross-check `get_trail_status` in the account; logs during the disabled window are permanently missing from that trail.

---

### 5. S3 bucket made public (policy / ACL / BPA changes)

**Maps to:** [Find Public S3 Buckets](#6-find-public-s3-buckets), Wiz public bucket alert.

**Athena:**

```sql
SELECT
  eventtime,
  eventname,
  useridentity.arn,
  sourceipaddress,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN (
    'PutBucketPolicy', 'PutBucketAcl', 'PutPublicAccessBlock',
    'DeletePublicAccessBlock', 'PutBucketPublicAccessBlock'
  )
  AND eventtime >= current_timestamp - interval '7' day
ORDER BY eventtime DESC;
```

```sql
-- Narrow to a specific bucket from the Wiz finding
SELECT eventtime, eventname, useridentity.arn, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND requestparameters LIKE '%sensitive-analytics-bucket%'
  AND eventtime >= current_timestamp - interval '7' day
ORDER BY eventtime;
```

**Splunk:**

```spl
index=aws_ct eventSource=s3.amazonaws.com
  (EventName=PutBucketPolicy OR EventName=PutBucketAcl OR EventName=PutPublicAccessBlock
   OR EventName=DeletePublicAccessBlock OR EventName=PutBucketPublicAccessBlock) earliest=-7d@d
| table _time EventName UserIdentity.Arn SourceIpAddress requestParameters
| sort - _time
```

---

### 6. IAM admin attachment / role changes

**Maps to:** [Find IAM Roles with Admin Access](#7-find-iam-roles-with-admin-access).

**Athena:**

```sql
SELECT
  eventtime,
  eventname,
  useridentity.arn,
  sourceipaddress,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN (
    'AttachRolePolicy', 'AttachUserPolicy', 'PutRolePolicy',
    'CreatePolicyVersion', 'AddUserToGroup', 'UpdateAssumeRolePolicy'
  )
  AND eventtime >= current_timestamp - interval '7' day
ORDER BY eventtime DESC;
```

**Splunk:**

```spl
index=aws_ct eventSource=iam.amazonaws.com earliest=-7d@d
  (EventName=AttachRolePolicy OR EventName=AttachUserPolicy OR EventName=PutRolePolicy
   OR EventName=CreatePolicyVersion OR EventName=AddUserToGroup)
| search requestParameters.policyArn="*AdministratorAccess*"
   OR requestParameters.policyArn="*IAMFullAccess*"
| table _time EventName UserIdentity.Arn SourceIpAddress requestParameters
```

---

### 7. VPC Flow Logs: external IP to a compromised instance

**Maps to:** GuardDuty credential exfil "outside AWS"; correlate stolen creds source IP with instance ENI.

**Athena:**

```sql
-- Inbound ACCEPT to a known instance private IP (replace IP and date partition)
SELECT
  start,
  srcaddr,
  dstaddr,
  srcport,
  dstport,
  protocol,
  bytes,
  interface_id,
  action
FROM vpc_flow_logs
WHERE dstaddr = '10.0.1.50'
  AND action = 'ACCEPT'
  AND srcaddr NOT LIKE '10.%'           -- exclude RFC1918 source (adjust to VPC CIDR)
  AND date >= date '2026-05-23'
ORDER BY start;
```

```sql
-- Top talkers to the instance ENI in the incident window
SELECT
  srcaddr,
  dstport,
  SUM(bytes) AS total_bytes,
  COUNT(*) AS flow_count
FROM vpc_flow_logs
WHERE interface_id = 'eni-0abc123def456'
  AND action = 'ACCEPT'
  AND date >= date '2026-05-23'
GROUP BY srcaddr, dstport
ORDER BY total_bytes DESC
LIMIT 50;
```

**Splunk:**

```spl
index=aws_vpcflow dest_ip=10.0.1.50 action=ACCEPT earliest=-72h@h
  NOT (src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16)
| stats sum(bytes) as total_bytes count by src_ip dest_port protocol
| sort - total_bytes
```

```spl
index=aws_vpcflow interface_id=eni-0abc123def456 action=ACCEPT earliest=-72h@h
| stats sum(bytes) as total_bytes count by src_ip dest_port
| sort - total_bytes
```

**Depth probe:** Flow logs show L3/L4 only; TLS SNI and HTTP host are not visible. For application-layer SSRF, pair with ALB/WAF logs and CloudTrail `AssumeRole` / instance role usage.

---

### 8. VPC Flow Logs: outbound C2 or data exfil from compromised instance

**Maps to:** Section 6 outbound restriction; Trojan/C2 GuardDuty finding types.

**Athena:**

```sql
-- Outbound ACCEPT from instance private IP to internet (non-RFC1918 dest)
SELECT
  start,
  srcaddr,
  dstaddr,
  srcport,
  dstport,
  protocol,
  bytes,
  interface_id
FROM vpc_flow_logs
WHERE srcaddr = '10.0.1.50'
  AND action = 'ACCEPT'
  AND dstaddr NOT LIKE '10.%'
  AND dstaddr NOT LIKE '172.16.%'
  AND dstaddr NOT LIKE '192.168.%'
  AND date >= date '2026-05-23'
ORDER BY bytes DESC;
```

```sql
-- Heavy egress on 443 (possible C2 over HTTPS)
SELECT
  dstaddr,
  SUM(bytes) AS total_bytes,
  COUNT(*) AS connections
FROM vpc_flow_logs
WHERE srcaddr = '10.0.1.50'
  AND dstport = 443
  AND action = 'ACCEPT'
  AND date >= date '2026-05-23'
GROUP BY dstaddr
ORDER BY total_bytes DESC
LIMIT 20;
```

**Splunk:**

```spl
index=aws_vpcflow src_ip=10.0.1.50 action=ACCEPT earliest=-72h@h
  NOT (dest_ip=10.0.0.0/8 OR dest_ip=172.16.0.0/12 OR dest_ip=192.168.0.0/16)
| stats sum(bytes) as total_bytes count by dest_ip dest_port protocol
| sort - total_bytes
```

---

### 9. VPC Flow Logs: inbound recon (port probes)

**Maps to:** `Recon:EC2/PortProbeUnprotectedPort`, open SG on port 80.

**Athena:**

```sql
-- REJECT inbound to instance (scanner hitting closed or filtered ports)
SELECT
  srcaddr,
  dstport,
  COUNT(*) AS reject_count
FROM vpc_flow_logs
WHERE dstaddr = '10.0.1.50'
  AND action = 'REJECT'
  AND date >= date '2026-05-23'
GROUP BY srcaddr, dstport
ORDER BY reject_count DESC
LIMIT 50;
```

```sql
-- ACCEPT inbound on port 80 from internet (matches open SG scenario)
SELECT
  start,
  srcaddr,
  dstport,
  bytes
FROM vpc_flow_logs
WHERE dstaddr = '10.0.1.50'
  AND dstport = 80
  AND action = 'ACCEPT'
  AND srcaddr NOT LIKE '10.%'
  AND date >= date '2026-05-23'
ORDER BY start;
```

**Splunk:**

```spl
index=aws_vpcflow dest_ip=10.0.1.50 action=REJECT earliest=-24h@h
| stats count by src_ip dest_port
| sort - count
```

---

### 10. Practice incident: join CloudTrail identity to VPC source IP

Narrate the correlation; no single query joins both sources without a common key (IP, time, ENI).

**Step A (CloudTrail):** external IP using the stolen key

```sql
SELECT DISTINCT sourceipaddress
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'ASIA1234567890EXAMPLE'
  AND eventtime >= current_timestamp - interval '72' hour;
```

**Step B (VPC Flow Logs):** confirm that IP reached the instance

```sql
SELECT start, srcaddr, dstaddr, dstport, bytes, action
FROM vpc_flow_logs
WHERE srcaddr = '203.0.113.42'    -- IP from step A
  AND dstaddr = '10.0.1.50'
  AND action = 'ACCEPT'
  AND date >= date '2026-05-23'
ORDER BY start;
```

**Splunk (transaction across indexes):**

```spl
index=aws_ct UserIdentity.AccessKeyId="ASIA1234567890EXAMPLE" earliest=-72h@h
| stats values(SourceIpAddress) as attacker_ips
| mvexpand attacker_ips
| join attacker_ips
    [ search index=aws_vpcflow earliest=-72h@h action=ACCEPT
      | eval attacker_ips=src_ip
      | stats count sum(bytes) as total_bytes by src_ip dest_ip dest_port ]
```

**What this demonstrates:** CloudTrail proves **API abuse**; flow logs prove **network path**. Together they support the story: SSRF on port 80 → creds from IMDS → API calls from attacker IP → optional outbound C2.

---

### CloudTrail Lake (optional mention)

If the org uses **CloudTrail Lake** instead of Athena on S3:

```sql
-- Lake SQL (event data store); table name is the EDS id
SELECT eventTime, eventName, sourceIpAddress, userIdentity.accessKeyId
FROM 01234567-89ab-cdef-0123-456789abcdef
WHERE userIdentity.accessKeyId = 'ASIA1234567890EXAMPLE'
  AND eventTime > '2026-05-23 00:00:00'
ORDER BY eventTime ASC;
```

Lake avoids manual partition columns and supports org-wide stores; syntax is close enough to Athena for interview discussion.

---

### Quick reference: investigation tool pick


| Question                          | First look                | Deep hunt                            |
| --------------------------------- | ------------------------- | ------------------------------------ |
| What APIs did this key call?      | `lookup_events`           | Athena / Splunk on CloudTrail        |
| Did they read S3 objects?         | Same (if data events on)  | Athena `GetObject` filter            |
| Who stopped CloudTrail?           | GuardDuty Stealth finding | `StopLogging` in Athena / Splunk     |
| Who made the bucket public?       | Wiz Issue                 | `PutBucketPolicy` / BPA APIs         |
| Did attacker IP hit the instance? | GuardDuty source IP       | VPC Flow Logs `srcaddr` → `dstaddr`  |
| Is the instance calling out?      | Runtime / GD C2 finding   | Flow logs egress from `srcaddr`      |
| Port scan / open port 80?         | GD Recon finding          | Flow logs `REJECT` / `ACCEPT` on :80 |


---

## Prevention: Service Control Policies

SCPs are guardrails applied at the AWS Organization level. They don't grant permissions; they set the maximum boundary of what's allowed across all accounts in an OU. Even if an IAM admin in a department account attaches AdministratorAccess to a role, an SCP can block the dangerous action. This is the preventive control layer that stops the misconfigurations before they happen. In the interview, propose SCPs in the "harden" step to show organizational-level thinking, not just per-account fixes.

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

Restrict operations to approved regions and block accepting VPC peering from outside the organization. (Outbound peering requests to external VPCs still need Config/tag guardrails; SCPs cannot evaluate peer CIDRs on `CreateVpcPeeringConnection`.)

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

At the "harden" step of the incident walkthrough, say something like:

> "Beyond fixing this specific misconfiguration, I'd propose org-level SCPs so this class of issue can't recur in any account. For example, we'd deny StopLogging across all member accounts, require IMDSv2 on every EC2 launch, and block public S3 access overrides. These are guardrails that apply even if a department admin has full IAM permissions in their own account; the SCP is the ceiling they can't exceed."

This framing matters because it shows the fix is not just the incident; it closes the gap for the whole org. It also connects naturally to the multi-department setup the recruiter described.

---

## Nintendo-Specific Angles

### How to Frame Answers for Their Environment

The scenario is *"a similar company to NOA, with multiple departments using AWS services to store and transform data, and customer-facing online web services."* Relevant context: Nintendo Switch Online, eShop, game analytics pipelines, marketing sites.

- **Multi-department = multi-account:** Each department (game dev, online services, marketing, data analytics) likely has its own AWS account under an Organization. Answers should assume cross-account visibility and centralized security tooling.
- **"Store and transform data":** S3 + Glue/Athena/EMR pipelines. Data security (encryption, access policies, data perimeters) is a first-class concern. Unreleased game assets in S3 are high-value targets.
- **"Customer-facing web services":** ALBs, EC2/ECS, API Gateway. Public-facing attack surface. Security group hygiene, WAF configuration, and DDoS protection (Shield) are relevant.
- **Wiz preference:** They use Wiz for CSPM. Wiz provides a graph-based view of attack paths (e.g., "this publicly exposed EC2 instance has a role that can read from an S3 bucket containing PII." If Wiz experience exists, discuss attack path visualization. Otherwise, describe the concept and willingness to learn the specific tool quickly.
- **Sony experience:** Sony is another gaming/entertainment company with massive AWS footprint and similar security challenges. Draw direct parallels when answering: "at Sony, we handled multi-account security by..." Strong differentiator.

### Questions to Ask Them

- "How many AWS accounts are you managing, and do you use a centralized security account for GuardDuty and Security Hub? What does your Org/OU structure look like?"
- "What does your IR runbook process look like today: is it documented, or are you building it out?"
- "How do you handle security for game launch events or holiday seasons when infrastructure scales rapidly?"
- "Is there an on-call rotation? What does that look like? What are the most common pageable events? What is the escalation path?"
- "What's the split between proactive engineering (hardening, automation) and reactive work (incidents, tickets) in this role?"
- "How does the NOA security team coordinate with the global team in Japan? Are there opportunities for in-person collaboration there?"
- "Given the small size of your team, how does that impact how you support each other?"

---

## Reference: The Capital One Breach

The canonical cloud security incident; good to reference if the scenario is similar.

- 1. Attacker exploited SSRF vulnerability in a misconfigured ModSecurity WAF on EC2.
- Queried IMDSv1 (`169.254.169.254`) to get temp credentials for the `ISRM-WAF-Role`.
- That role had excessive permissions: `s3:ListBucket`, `s3:GetObject` on all buckets, plus `kms:Decrypt`.
- Exfiltrated 30 GB / 106M individuals' credit application data.
- **Every evaluation area failed:** IMDSv1 (no session tokens), overly permissive IAM role, no SG egress filtering, no S3 data event logging to catch the exfil in real-time, no outbound network segmentation, and CloudTrail analysis happened only after the breach was reported months later.
- **IMDSv2 would have blocked** the SSRF path: PUT request + headers are beyond most SSRF capabilities.

