# Nintendo Cloud Security Engineer: Final Interview Prep

**Final round (60 minutes, Microsoft Teams).** Interviewers are a **Principal Cloud Systems Engineer** and a **Sr Cloud Systems Engineer** from the **cloud platform engineering** team. Expect a conversational working session about how security embeds in platform operations, standards, and day-to-day AWS design. **No live coding** in this round.

For optional self-study on incident response, GuardDuty/Wiz triage, and scripting patterns, see [Hands-On Interview Prep.md](Hands-On%20Interview%20Prep.md). For behavioral and resume-aligned stories, see [sample questions and responses.md](sample%20questions%20and%20responses.md).


| Detail           | Value                                              |
| ---------------- | -------------------------------------------------- |
| Duration         | 60 min                                             |
| Format           | Teams; Principal Cloud Systems Engineer + Sr Cloud Systems Engineer (platform engineering) |
| Decision timeline | Shortly after this round                          |
| Prior round      | Security engineering: live incident scenario (not repeated here) |


## Table of contents

- [How This Round Differs](#how-this-round-differs)
- [1. EC2 Compromise, Evidence, and VPC](#1-ec2-compromise-evidence-and-vpc)
- [2. Public RDS and Third-Party Access](#2-public-rds-and-third-party-access)
- [3. AWS Governance Tools and Security Controls](#3-aws-governance-tools-and-security-controls)
- [4. AWS Systems Manager Session Manager](#4-aws-systems-manager-session-manager)
- [5. IAM Access Analyzer](#5-iam-access-analyzer)
- [6. AWS Secrets Manager](#6-aws-secrets-manager)
- [7. Policy Exception Process](#7-policy-exception-process)
- [Cross-Cutting Scenarios](#cross-cutting-scenarios)
- [Platform Ops and Production-Safe IR (Likely Questions)](#platform-ops-and-production-safe-ir-likely-questions)
- [Questions to Ask the Platform Team](#questions-to-ask-the-platform-team)
- [Day-Before Checklist](#day-before-checklist)


---

## How This Round Differs

Platform engineers own account vending, networking baselines, shared services, and the guardrails teams hit when deploying workloads. Questions will still be security-heavy, but the lens is **operational**: what breaks when a control is enforced, how exceptions get handled, and how security partners with platform instead of blocking delivery. Answers should be **conceptual and conversational**; no live scripting or whiteboard coding.

**Answer structure that lands well:**

1. **State the risk** in one sentence (blast radius, data class, exposure).
2. **Name the control** (preventive vs detective; SCP vs Config vs GuardDuty).
3. **Describe the platform pattern** (standard landing zone, SSM-only access, private RDS).
4. **Acknowledge tradeoffs** (developer velocity, third-party integrations, legacy apps).
5. **Close with governance** (exception path, expiry, compensating controls, IaC as source of truth).

**Sony-scale anchors to weave in when relevant:** multi-org AWS estates, per-account CloudTrail delivery to a central bucket, SCPs on PSN and enterprise OUs, migration from bastion/jump hosts to SSM, Wiz + native AWS controls for steady-state posture.


---

## 1. EC2 Compromise, Evidence, and VPC

> **Recruiter focus:** EC2 instances, investigating compromises and evidence, EC2 VPC.

### Why the platform team cares

Compromised instances touch **network design** (subnet placement, SGs, endpoints), **access patterns** (SSH vs SSM), and **fleet standards** (IMDSv2, quarantine SGs, logging). Platform wants repeatable containment that preserves evidence without ad-hoc firefighting.

### VPC context for investigations

| Layer | What it tells investigators |
| ----- | --------------------------- |
| **Subnet** | Public subnet + IGW route = direct internet path; private subnet egress usually via NAT or endpoints only |
| **Security group** | Stateful allow/deny at ENI; common entry: `0.0.0.0/0` on 22/3389/8080 |
| **NACL** | Stateless subnet edge; useful when SG looks correct but traffic still blocked or allowed unexpectedly |
| **VPC Flow Logs** | `srcaddr`, `dstaddr`, ports, `ACCEPT`/`REJECT`; proves C2, lateral movement, exfil volume (not payload) |
| **DNS query logs** | GuardDuty input; C2 domain resolution even when IP is ephemeral |
| **VPC endpoints** | Private path to S3/SSM/CloudWatch; reduces exposure but endpoint policies still need scoping |

**IMDSv2:** Enforce `HttpTokens=required` account-wide (SCP on `RunInstances` with `ec2:MetadataHttpTokens`). IMDSv1 + SSRF on a web app + overprivileged instance role is the Capital One pattern; platform and security both own the baseline.

### Evidence preservation (order matters)

1. **Do not terminate** the instance first; memory is lost and EBS may be the only disk artifact.
2. **Snapshot EBS volumes** (`create_snapshot`) with IR tags before network changes.
3. **Isolate network:** swap to a pre-staged **quarantine SG** (deny all inbound/outbound); tag with original SG IDs for rollback.
4. **Revoke active credentials:** inline deny on the instance role with `aws:TokenIssueTime` condition; rotate or remove static keys if any exist.
5. **Collect API trail:** CloudTrail for actions by the instance role's session key (`ASIA...`); GuardDuty for `InstanceCredentialExfiltration`, `C&CActivity`, Runtime Monitoring findings if enabled.
6. **Correlate network:** VPC Flow Logs + GuardDuty DNS findings for the instance ENI.
7. **Optional host forensics:** SSM Session Manager or `SendCommand` for disk/memory collection if Runtime Monitoring or EDR is not present (requires prior IAM and agent setup).

Deep dive: [Quarantine a Compromised Instance](Hands-On%20Interview%20Prep.md#3-quarantine-a-compromised-instance), [Log Analysis: Athena & Splunk](Hands-On%20Interview%20Prep.md#log-analysis-athena--splunk).

### Likely questions

- "Walk through how you'd investigate a compromised EC2 instance."
- "What evidence would you collect before rebuilding the host?"
- "How does VPC design help or hurt containment?"

### Strong answer (60-second version)

GuardDuty or Wiz surfaces the instance; correlate with CloudTrail for API abuse using the instance profile role and with VPC Flow Logs for external IPs and unusual egress. Snapshot EBS, apply a quarantine SG, revoke role sessions, then rebuild from a known-good AMI while root cause is traced (open SG, IMDSv1, vulnerable app, stolen keys). Prevent recurrence with private subnets, ALB-only ingress, IMDSv2 SCP, restricted egress, and SSM instead of SSH.

### Fleet audit priorities (no scripting required)

When asked how to find similar risk across the estate, name **Config rules**, **Security Hub**, or **Wiz** findings for:

- EC2 instances that do not require IMDSv2 (`HttpTokens` optional)
- Instances in public subnets or with public IPs plus internet-open security group rules
- Missing VPC Flow Logs on subnets or VPCs handling sensitive workloads

Highest priority overlap: **IMDSv1 allowed**, **public placement**, and **internet-open SG** on the same instance. Remediation path: launch template or account default for IMDSv2, SCP on `RunInstances`, and Config auto-remediation or pipeline gates. Route table inspection matters; `MapPublicIpOnLaunch` alone does not prove a path to an internet gateway.


---

## 2. Public RDS and Third-Party Access

> **Recruiter focus:** Public RDS, 3rd party access.

### Why public RDS is almost never acceptable

A publicly accessible RDS instance gets a **public DNS name** resolvable from the internet. Risk stack:

1. **`PubliclyAccessible=true`** on the instance.
2. **DB subnet group** includes subnets with routes to an **Internet Gateway** (or the instance is placed such that AWS assigns public accessibility).
3. **Security group** allows database ports (`3306` MySQL, `5432` Postgres, `1433` SQL Server, etc.) from `0.0.0.0/0` or overly broad CIDRs.
4. **Weak auth:** static master password in config, no rotation, shared credentials with a vendor.

GuardDuty **RDS Protection** (login anomaly findings) helps detect brute force and unusual logins but does not replace removing public exposure.

### Correct patterns for app and third-party access

| Pattern | When to use | Security notes |
| ------- | ----------- | -------------- |
| **Private RDS in DB subnets** | Default for all internal apps | App tier in private subnets; SG allows DB port **from app SG only** |
| **RDS Proxy** | Connection pooling, IAM auth, credential rotation | Hides direct DB endpoint; integrates with Secrets Manager |
| **IAM database authentication** | Eliminate long-lived DB passwords where supported | Short-lived auth tokens; audit via CloudTrail |
| **Secrets Manager** | Store master and app credentials | Auto-rotation via Lambda; apps fetch at runtime |
| **Site-to-Site VPN / Direct Connect** | On-prem or fixed vendor network | Vendor connects to corporate network, not the public internet |
| **AWS PrivateLink** | SaaS or partner consumes a **private** endpoint | No public RDS; partner attaches to VPC endpoint service |
| **Dedicated read replica + scoped access** | Vendor needs read-only analytics | Replica in isolated subnet; no write path; time-bound access |
| **Bastion/SSM port forwarding** | Break-glass DBA access only | Session logged; no permanent `0.0.0.0/0` on 5432 |

**Third-party access framing:** Prefer **network path control** (PrivateLink, VPN, allowlisted partner CIDR via SG) plus **identity control** (IAM DB auth, unique credentials per vendor, rotation). Avoid "make RDS public for convenience." If a vendor requires outbound-initiated connectivity, the vendor often connects **into** the customer environment, not the reverse.

### Likely questions

- "A partner says they need access to our RDS. What do you recommend?"
- "How would you find and remediate publicly accessible databases?"
- "What compensating controls apply if a legacy app truly cannot move off public access?" (lead toward **time-bound exception** + IP allowlist + WAF/network ACL + enhanced logging, not indefinite public exposure)

### Fleet audit priorities (no scripting required)

- **AWS Config** rule `rds-instance-public-access-check` flags `PubliclyAccessible=true`.
- **Security Hub** aggregates RDS public-access findings org-wide.
- **Manual follow-up:** attached security groups for `0.0.0.0/0` on engine ports, DB subnet group placement (routes to IGW), encryption at rest, IAM database authentication where supported, credentials in Secrets Manager (not config files).


---

## 3. AWS Governance Tools and Security Controls

> **Recruiter focus:** AWS governance tools and security controls.

### Control stack (how platform teams think)

```text
Identity Center (SSO) → Permission sets per account/role
        ↓
Service Control Policies (org ceiling; deny wins)
        ↓
Account baselines (CloudFormation/Terraform landing zone)
        ↓
IAM policies + permission boundaries (actual grants)
        ↓
Resource policies (S3, KMS, SNS, cross-account)
        ↓
Detective: Config, Security Hub, GuardDuty, Access Analyzer, Wiz
        ↓
Response: EventBridge → Lambda/SSM Automation, IR runbooks
```

### Services to name confidently

| Service | Role in governance |
| ------- | ------------------ |
| **AWS Organizations** | Multi-account structure, OUs, SCPs, delegated admins |
| **Control Tower** (if used) | Opinionated landing zone; guardrails via SCPs and Config |
| **SCPs** | Org-wide **maximum** permissions; cannot grant, only deny/limit |
| **AWS Config** | Configuration history + rules; continuous compliance; auto-remediation |
| **Security Hub** | Aggregates GuardDuty, Config, Inspector, Access Analyzer; CIS benchmark |
| **GuardDuty** | Threat detection (CloudTrail, VPC Flow, DNS, S3, EKS, RDS, Runtime) |
| **CloudTrail** | Org/multi-account API audit; S3 + Lake/Athena for investigations |
| **IAM Access Analyzer** | External access and unused access findings |
| **Service Catalog / AFT** | Standardized account provisioning with security baked in |

**SCP vs Config vs GuardDuty:** SCPs **prevent** disallowed actions (e.g., `StopLogging`, public SG authorize for non-network roles). Config **detects** drift from desired state (and can remediate). GuardDuty **detects** adversary behavior and misconfigurations with threat intel. All three belong in a mature program; none replaces the others.

Sony-relevant examples in [Prevention: Service Control Policies](Hands-On%20Interview%20Prep.md#prevention-service-control-policies): deny GuardDuty disable, CloudTrail tampering, dangerous IAM policy attach, IMDSv2 on launch.

### Likely questions

- "How would you enforce security standards across hundreds of accounts?"
- "What's the difference between preventive and detective controls in AWS?"
- "How do you work with platform when a new AWS service needs to be adopted?"

### Strong answer themes

- **IaC source of truth:** Standards live in Terraform/CloudFormation modules in a central repo; drift is a finding, not the norm.
- **Delegated admin:** Security services (GuardDuty, Config, Access Analyzer) registered to a security account with org-wide visibility.
- **Tiered OUs:** Stricter SCPs on production; sandbox OUs looser but still no disabling logging or org leave.
- **Metrics:** % accounts with Config recording, open critical Security Hub findings, mean time to remediate Config noncompliance.


---

## 4. AWS Systems Manager Session Manager

> **Recruiter focus:** AWS Secure Sessions Manager (Session Manager, part of **AWS Systems Manager**).

### What Session Manager replaces

Traditional **SSH/RDP on port 22/3389** requires inbound SG rules, key management, and often bastion hosts. Session Manager provides **browser/CLI shell access over AWS APIs** with **no inbound ports** on the instance.

### Prerequisites (platform checklist)

| Requirement | Detail |
| ----------- | ------ |
| **SSM Agent** | Preinstalled on Amazon Linux 2/2023 and many AMIs; must be running |
| **Instance profile** | At minimum `AmazonSSMManagedInstanceCore` (tighten beyond managed policy in production) |
| **Network path** | Outbound HTTPS to SSM endpoints, or **VPC interface endpoints** for `ssm`, `ssmmessages`, `ec2messages` |
| **IAM for operators** | `ssm:StartSession` on target instances/resources; restrict by tag, account, or permission set |
| **Logging** | Session Manager preferences: log to S3 and/or CloudWatch Logs; optional KMS encryption |

### Security advantages (talking points)

- **Auditability:** Session start/end and command transcripts in S3/CloudWatch (when enabled).
- **No SSH keys on disk:** Access tied to IAM Identity Center / SSO roles.
- **No bastion SG sprawl:** Removes `0.0.0.0/0` jump box patterns.
- **Port forwarding:** Encrypted tunnel for admin DB access without opening RDS to the internet (still log and restrict).

### Risks to acknowledge (shows depth)

- `AmazonSSMManagedInstanceCore` also enables **`ssm:SendCommand`**; scope custom policies if only Session Manager is intended.
- Compromised **operator IAM** becomes server access; enforce MFA, short session duration, and least privilege on `ssm:StartSession`.
- Instances without endpoints in **fully isolated subnets** need endpoint policy design or hybrid access model.

**Sony anchor:** Estate moved from bastion/jump hosts to SSM for remote access; aligns with recruiter emphasis and [Security Group Traffic](Hands-On%20Interview%20Prep.md#3-security-group-traffic) guidance (no internet-open 22).

### Likely questions

- "Why Session Manager instead of a bastion?"
- "What has to be in place before SSM works in a private subnet?"
- "How do you audit who accessed a production instance?"

### Session logging (conceptual policy fragment)

Session Manager account preferences (set via SSM document or console) should enable:

- **S3 logging** with a dedicated bucket, encryption, and bucket policy denying non-security writes.
- **CloudWatch Logs** for near-real-time alerting on production session starts.
- **KMS CMK** for session data encryption where compliance requires it.


---

## 5. IAM Access Analyzer

> **Recruiter focus:** AWS IAM Access Analyzer.

### What it does

Access Analyzer continuously evaluates resource policies (S3, IAM roles, KMS, Lambda, SQS, etc.) and reports **resources shared with external entities** (outside the account or organization).

| Capability | Use |
| ---------- | --- |
| **External access findings** | "This S3 bucket policy allows `Principal: *`" or cross-account access from unknown account |
| **Unused access analysis** | Identifies permissions granted but not used (CIEM-adjacent; complements Wiz CIEM) |
| **Policy validation / generation** | IAM policy generator from CloudTrail activity (least-privilege refinement) |
| **Archive rules** | Suppress known-intentional external access with documented justification (ties to exception process) |

**Organization trail:** Enable Access Analyzer as a **delegated administrator** for org-wide external access visibility from the security account.

### Workflow platform + security share

1. **Finding triage:** Is external access intentional (CDN, partner account, public website bucket)?
2. **If unintentional:** Remediate policy; run IaC pipeline to prevent regression.
3. **If intentional:** Link to **exception record** (owner, expiry, compensating controls); archive rule with ticket ID.
4. **Revalidation:** Quarterly review of archived findings; Access Analyzer reopens if policy widens.

### Likely questions

- "How does Access Analyzer differ from Wiz?"
- "How would you use Access Analyzer in a multi-account org?"
- "What do you do with a finding that's a false positive?"

### Positioning vs Wiz

**Wiz** maps attack paths and toxic combinations on the security graph (steady-state CNAPP). **Access Analyzer** is native, policy-centric, and ideal for **provable external exposure** on AWS resource policies. Use both; Access Analyzer findings feed Security Hub and pair well with Config `s3-bucket-public-read-prohibited` and similar rules.


---

## 6. AWS Secrets Manager

> **Recruiter focus:** AWS Secrets Manager.

### Core capabilities

| Feature | Detail |
| ------- | ------ |
| **Central secret storage** | JSON key/value; encrypted with KMS (AWS-managed or CMK) |
| **Rotation** | Built-in rotation for RDS, Redshift, DocumentDB via Lambda; custom rotation for app secrets |
| **Fine-grained access** | IAM `secretsmanager:GetSecretValue` scoped by secret ARN and `aws:SourceVpc` conditions |
| **Cross-account access** | Resource policy on secret + IAM in consumer account |
| **Audit** | CloudTrail logs `GetSecretValue`, `RotateSecret`, `PutSecretValue` |

### Secrets Manager vs SSM Parameter Store

| | **Secrets Manager** | **Parameter Store (SecureString)** |
| - | ------------------- | ---------------------------------- |
| **Rotation** | Native scheduled rotation | Manual or custom |
| **Cost** | Per-secret monthly + API | Standard parameters cheaper |
| **Best for** | DB credentials, API keys needing rotation | Config values, non-rotating secrets, wide deployment via SSM |

**Rule:** No secrets in user data, plain environment variables in task definitions, Git repos, or unencrypted S3. Apps fetch at runtime via IAM role.

### RDS integration pattern

1. Store master credentials in Secrets Manager.
2. Enable **automatic rotation** (single-user or alternating-user strategy for high availability).
3. Application or **RDS Proxy** retrieves credentials via IAM role.
4. Prefer **IAM database authentication** for apps that support it to reduce static password dependency.

### Likely questions

- "How would you rotate database credentials without downtime?"
- "How do you prevent developers from hardcoding secrets?"
- "When would you choose Vault or CyberArk over Secrets Manager?" (multi-cloud, advanced dynamic secrets, existing enterprise vault standard; at Sony, Vault/CyberArk appeared alongside AWS-native services)

### Rotation caveats (interview depth)

- Rotation Lambda must reach the database (VPC placement, SG rules).
- Applications must **retry** on secret version change or use RDS Proxy.
- Break-glass credentials stored separately with stricter IAM and no broad `GetSecretValue` on `*`.


---

## 7. Policy Exception Process

> **Recruiter focus:** Policy exception process.

Exact Nintendo workflow may differ; describe a **credible enterprise pattern** that platform and security teams commonly share.

### Typical exception lifecycle

```text
Request → Risk assessment → Compensating controls → Approvals → Time-bound grant → Monitor → Revalidate or expire
```

| Step | Actions |
| ---- | ------- |
| **1. Request** | Ticket with business owner, resource IDs, requested deviation (e.g., inbound 443 from vendor CIDR, legacy public RDS for 90 days), and expiry date |
| **2. Risk assessment** | Data classification, blast radius, alternatives considered (PrivateLink, VPN, read replica) |
| **3. Compensating controls** | Enhanced logging, WAF, IP allowlist, dedicated SG, GuardDuty/Config alerts, manual review cadence |
| **4. Approval** | Security + platform (+ GRC for regulated data); dual approval for production |
| **5. Implementation** | **IaC change** or tagged exception (not console-only drift); Access Analyzer archive rule linked to ticket |
| **6. Monitoring** | Config rule exclusion with expiry; SIEM detection for abuse of excepted resource |
| **7. Closure** | Auto-expire or renew with re-approval; permanent exceptions require executive risk acceptance |

### Principles to state clearly

- **Exceptions are time-bound**, not permanent policy rewrites.
- **Default deny remains**; exceptions are narrow (specific SG rule, specific bucket, specific account).
- **Compensating controls are mandatory**; "accept risk" without mitigation is not a real exception.
- **Platform owns delivery**, security owns risk acceptance; both sign for production.
- **IaC is the enforcement mechanism** where possible (Terraform module parameter `exception_id`, `expires_on` tag).

### Likely questions

- "A team needs an exception to the standard. What happens?"
- "How do you prevent exception sprawl?"
- "Tell me about a time you pushed back on an exception request." (Use Wiz Code rollout or SCP tightening story from Sony; see [sample questions and responses.md](sample%20questions%20and%20responses.md#9-behavioral--collaboration))

### Anti-patterns to call out

- Permanent `0.0.0.0/0` "just for testing"
- Console hotfixes with no ticket or expiry
- Archived Access Analyzer findings without owner or review date
- SCP exceptions granted org-wide instead of single-account OU placement


---

## Cross-Cutting Scenarios

Practice narrating these end-to-end; each touches multiple recruiter topics.

### Scenario A: Vendor needs database read access

**Bad:** Public RDS + shared password emailed to vendor.

**Good:** Read replica in private subnets; SG allows vendor **fixed egress IPs** only, or connectivity via **PrivateLink/VPN**; credentials in **Secrets Manager** with rotation; **IAM auth** where possible; **90-day exception** with Access Analyzer review; session/ query logging enabled.

### Scenario B: Compromised EC2 in a public subnet

Contain with **quarantine SG** and role session revoke; investigate via **CloudTrail + VPC Flow Logs**; forensics via **EBS snapshot** and **SSM** (not SSH); rebuild with **private subnet + ALB**, **IMDSv2**, **Session Manager** baseline; platform updates **launch template** and **Config remediation**.

### Scenario C: Config flags SG open to world on 22

**Detective:** Config rule + Security Hub finding.

**Preventive:** SCP restricting `AuthorizeSecurityGroupIngress` to network pipeline roles (see [SCP 3](Hands-On%20Interview%20Prep.md#scp-3-block-overly-permissive-security-groups)).

**Exception:** Time-bound break-glass with SSM preferred; if 22 must exist, `/32` vendor IP only, ticket, expiry, enhanced logging.

### Scenario D: Secret found in Git

Rotate immediately in **Secrets Manager**; invalidate old version; scan repo history; add **pre-commit/CI secret scanning**; enforce **IAM** so apps pull secrets at runtime, not from env files in Git.


---

## Platform Ops and Production-Safe IR (Likely Questions)

Platform engineers often evaluate whether security **understands production constraints**: shared services, change windows, blast radius of containment actions, and whether IR will **stop the bleeding without taking the platform down**.

### What they are really probing

| Concern | What a strong answer signals |
| ------- | ---------------------------- |
| **Availability** | Containment defaults to isolate-and-preserve, not terminate-and-pray |
| **Blast radius** | Actions are scoped to one account, instance, role, or SG; no org-wide surprises |
| **Change discipline** | Security coordinates with platform/on-call before disruptive steps |
| **Operational load** | Controls reduce toil (SSM, IaC, delegated admin), not endless tickets |
| **Shared ownership** | Runbooks, comms channels, and rollback plans exist before the incident |

### Production-safe IR principles (state these early if asked)

1. **Preserve evidence before disruptive change:** EBS snapshots, CloudTrail retention, tags documenting original SGs.
2. **Contain without destroying:** quarantine SG, revoke sessions, block egress to known bad IPs; avoid `TerminateInstances` until platform agrees or scope is proven.
3. **Prefer reversible network changes:** swap SGs (tag originals), avoid deleting subnets, NAT gateways, or shared ALB rules without a diagram review.
4. **Coordinate on shared infrastructure:** NAT, Transit Gateway, Route 53, centralized logging buckets, org-wide SCPs affect more than one team.
5. **Communicate:** incident bridge, explicit "planned impact" before IAM denies, secret rotation, or bucket policy changes on production paths.
6. **Separate detective from disruptive:** gather CloudTrail and flow logs first; auto-remediation in prod often waits for human confirmation unless policy is pre-approved.

### Likely questions: security impact on platform operations

- How will security engage when platform wants to roll out a **new AWS service** or region?
- How do security standards affect **account vending** and **landing zone** updates (SCPs, Config rules, mandatory logging)?
- What happens when a **Config rule** or **Security Hub** finding blocks a production deployment pipeline?
- How should teams request **exceptions** without bypassing platform IaC or creating console drift?
- How does security reduce **false positives** and on-call noise from GuardDuty, Wiz, or Access Analyzer?
- Who owns **remediation** when a finding is in a shared VPC, shared RDS, or platform-managed networking stack?
- How will security participate in **change management** (CAB, maintenance windows) for controls that touch production?
- What is security's stance on **auto-remediation** in production vs sandbox OUs?

### Likely questions: incident response without outages

- Walk through **containment** for a compromised EC2 in a **production Auto Scaling group** or behind an ALB.
- Would security **terminate** the instance immediately? Why or why not?
- How does security **quarantine** an instance without breaking health checks or draining the ASG incorrectly?
- What is the plan if the compromised host runs a **shared service** (CI runner, bastion legacy, monitoring agent, license server)?
- How would security handle a suspect instance that is the **only** task in a critical path before a launch or event window?
- When is it appropriate to apply an **inline deny-all** on an IAM role vs rotate credentials vs detach the instance profile?
- How does security avoid **breaking application connectivity** when tightening SG egress during an active incident?
- What steps are taken before **rotating Secrets Manager** credentials used by a live RDS-backed app?
- How does security investigate **without disabling** CloudTrail, VPC Flow Logs, or centralized logging (and what if an attacker already did)?
- How are **false positives** ruled out before production containment (e.g., pen test IP, known scanner, approved vendor)?

### Likely questions: collaboration and escalation

- Who does security call **first** when a finding touches production: platform on-call, app owner, or both?
- How are **runbooks** shared so platform can execute quarantine steps if security is off-hours?
- Describe a time security **pushed back** on a risky change; describe a time security **expedited** a fix for platform.
- How does security handle **disagreement** when risk acceptance differs (ship now vs block deploy)?
- What tooling access does security need in member accounts, and how is that **least-privilege** without blocking platform automation roles?

### Likely questions: governance actions with production blast radius

- Would security deploy an **org-wide SCP** during an active incident? Under what conditions?
- How are **SCP changes** tested in sandbox OUs before production OUs?
- What is the approach to **revoking cross-account roles** that platform pipelines use?
- How does security remediate **public S3 or public RDS** without deleting data or breaking a live integration?
- How are **Session Manager** sessions handled during IR (forensics vs operator access conflicting)?

### Scenario prompts (multi-part, very common)

**"GuardDuty flagged production instance `i-abc` in the payment OU. It's still serving traffic. What do you do?"**

Hit: confirm finding, loop platform on-call, snapshot/isolate options, preserve ASG capacity (launch replacement from clean AMI if needed), investigate in parallel, no unilateral terminate, post-incident hardening via launch template not one-off console edits.

**"We need to block an IP globally. Security wants to change the NACL. Concerns?"**

Hit: NACL is coarse and stateless; SG or WAF may be safer; shared subnets affect many instances; document rollback; prefer scoped block at WAF/ALB if HTTP-only threat.

**"Security wants to enable a new Config rule tomorrow that will flag half our SGs."**

Hit: pilot in non-prod OU, exception process for legacy, remediation playbook, pipeline integration, metrics on fix rate, not big-bang prod enforcement without notice.

### Answer hooks that resonate with platform engineers

- **"Contain first, kill last"** … quarantine SG and session revoke preserve disk and config for root cause; rebuild is planned with platform.
- **"Shared fate"** … before touching TGW, DNS, or org logging, identify dependents on a architecture diagram or CMDB.
- **"Reversible by design"** … tag `OriginalSecurityGroups`, use break-glass roles with time bounds, document rollback in the ticket.
- **"Same path as normal changes"** … post-incident fixes land in **Terraform/launch templates**, not permanent console exceptions.
- **"Availability is a security property"** … ransomware and destructive API calls are outages; controlled containment protects both.


---

## Questions to Ask the Platform Team

Thoughtful questions show partnership mindset:

- How are **landing zones** and **account vending** structured today (Control Tower, custom Terraform, hybrid)?
- Is **Session Manager** the standard for instance access, and are session logs centralized?
- How are **SCPs** tiered across sandbox vs production OUs?
- What **Config** rules or **Security Hub** standards are non-negotiable vs negotiable via exception?
- How does the platform team prefer security to engage (**shift-left** in pipelines vs gate at deploy time)?
- What does the **exception process** look like in practice (tooling, approvers, typical turnaround)?


---

## Day-Before Checklist

- [ ] Re-read recruiter focus areas (this doc §1–7).
- [ ] Skim [Hands-On Interview Prep.md](Hands-On%20Interview%20Prep.md) quarantine, CloudTrail, SG, and SCP sections only if deeper IR detail is needed (optional; no coding expected).
- [ ] Prepare 2–3 **collaboration stories** (Wiz Code with studios, SCP/IaC at Sony, IR containment).
- [ ] Prepare 1 **production-safe IR** story: contained a host without terminate, coordinated with ops, fixed via IaC/launch template.
- [ ] Prepare 1 **respectful pushback** story (exception denied or narrowed with compensating controls).
- [ ] Review [Platform Ops and Production-Safe IR](#platform-ops-and-production-safe-ir-likely-questions).
- [ ] Test Teams audio/video; have a quiet space for 60 minutes.
- [ ] Keep answers **concise first**, expand when asked; platform interviews run long on one topic if the discussion is good.

Good luck.
