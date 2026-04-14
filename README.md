# Cloud Security Engineer at Nintendo: Interview Study Guide

## By Blake Mennen

These are my personal study notes for the Nintendo of America Cloud Security Engineer interview.
The format is inspired by [gracenolan's Security Engineering study notes](https://github.com/gracenolan/Notes/blob/master/interview-study-notes-for-security-engineering.md).

The JD explicitly asks for: cloud security architecture, AWS (Wiz preferred), networking protocols
(TCP/IP, HTTP, DNS, TLS), IDS/IPS, cryptographic systems, identity management, RADIUS,
Python/scripting, incident response, SIEM, and vulnerability management.

---

### Contents

- [Interview Tips](#interview-tips)
- [Networking & Protocols](#networking--protocols)
- [Cloud Security & AWS](#cloud-security--aws)
- [Identity & Access Management](#identity--access-management)
- [Wiz / CNAPP / CSPM](#wiz--cnapp--cspm)
- [Infrastructure & Containers](#infrastructure--containers)
- [Cryptography & TLS](#cryptography--tls)
- [Threat Detection & SIEM](#threat-detection--siem)
- [Incident Response](#incident-response)
- [Vulnerability Management](#vulnerability-management)
- [Threat Modeling](#threat-modeling)
- [Compliance & Governance](#compliance--governance)
- [Python & Scripting](#python--scripting)
- [Security Themed Coding Challenges](#security-themed-coding-challenges)

---

## Interview Tips

**Think out loud.** Interviewers want to follow your reasoning, not just hear your conclusion.
If you're not sure, walk them through how you'd approach finding out.

**Lead with experience, then theory.** Anchor every answer in something you actually did before explaining the underlying concept.

**Own your level honestly.** "I contributed to this alongside a senior engineer" is a stronger answer
than overclaiming. Interviewers can tell and honesty builds trust.

**Use numbers.** Real examples: 1,000+ accounts, ~92% reduction in onboarding time, 2 hours to 10 minutes. Weave
them in naturally throughout, not just for the automation question.

**Prepare one strong IR story.** Know it cold in STAR format (Situation, Task, Action, Result).
Incident response questions are almost guaranteed.

**It's okay to say "I don't know."** Follow it with: "But here's how I'd approach finding out."

**Ask clarifying questions before answering complex scenarios.** "Before I answer, can I ask a few
questions about the environment?".

---

## Networking & Protocols

The JD calls these out explicitly: TCP/IP, HTTP, DNS, TLS, IDS/IPS, RADIUS, firewalls.
Don't underestimate this section — it's where cloud engineers often have gaps.

### OSI Model
- Know all 7 layers and what lives at each one.
- Security controls exist at every layer — be able to name one per layer.
- Layer 3 = IP routing. Layer 4 = TCP/UDP. Layer 7 = HTTP, DNS, application logic.

### TCP/IP
- TCP three-way handshake: SYN → SYN-ACK → ACK.
- SYN flood attacks exploit the half-open connection state.
- UDP is stateless — used for DNS, RADIUS, streaming.
- Know common port numbers: 22 (SSH), 443 (HTTPS), 53 (DNS), 1812 (RADIUS), 3389 (RDP).

### DNS
- Requests are UDP by default, TCP for large responses or zone transfers.
- Lookup order: local cache → recursive resolver → root → TLD → authoritative.
- Record types: A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail), NS (nameserver), PTR (reverse lookup), TXT (SPF/DKIM).
- DNS exfiltration: data encoded as subdomains. Doesn't appear in HTTP logs.
- DNS sinkholes: redirect malicious domains to a controlled IP for monitoring/blocking.
- DNS over HTTPS (DoH): encrypts DNS queries, prevents interception, but makes monitoring harder.
- DNSSEC: digitally signs DNS records to prevent spoofing/poisoning.

### HTTP / HTTPS
- HTTP is stateless. Sessions maintained via cookies or tokens.
- HTTPS = HTTP over TLS. Port 443.
- HTTP methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.
- Status codes: 200 (OK), 301/302 (redirect), 401 (unauthenticated), 403 (forbidden), 404 (not found), 500 (server error).
- Headers of interest: `Authorization`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`.

### Firewalls
- Stateless: filters on IP/port only, no connection tracking.
- Stateful: tracks connection state, allows return traffic automatically.
- Next-gen (NGFW): deep packet inspection, application awareness, IDS/IPS integration.
- AWS equivalents: Security Groups (stateful, instance-level), NACLs (stateless, subnet-level), AWS Network Firewall (NGFW-style).
- Default deny is the baseline posture — allow only what's needed.

### IDS vs IPS
- IDS (Intrusion Detection System): monitors and alerts. Passive. Does not block.
- IPS (Intrusion Prevention System): monitors and blocks. Inline. Can cause false-positive outages.
- Signature-based: matches known attack patterns. Fast but misses zero-days.
- Anomaly-based: learns normal behavior, flags deviations. More false positives.
- In AWS: GuardDuty is effectively an IDS. WAF can act as an IPS for web traffic.
- Placement: IDS out-of-band (copy of traffic), IPS inline (traffic must flow through it).

### DDoS
- Volumetric: flood bandwidth (UDP floods, amplification attacks).
- Protocol: exploit layer 3/4 (SYN flood, ping of death).
- Application layer: HTTP floods targeting specific endpoints (hardest to detect).
- AWS mitigations: AWS Shield (Standard free, Advanced paid), CloudFront, Route53 rate limiting, WAF rules.
- Rate limiting and geo-blocking are first-line defenses. Scrubbing centers for large volumetric attacks.

### RADIUS
- Remote Authentication Dial-In User Service. Port 1812 (auth), 1813 (accounting).
- Used for network access control — VPNs, Wi-Fi, 802.1X.
- Client (NAS) sends credentials to RADIUS server, which authenticates against a directory (AD, LDAP).
- Responses: Access-Accept, Access-Reject, Access-Challenge (for MFA).
- RADIUS uses shared secret between NAS and server — if compromised, all auth is at risk.

---

## Cloud Security & AWS

The core of this role. Use your work as the foundation for every answer and layer in the conceptual understanding.

### Multi-Account Architecture
- AWS Organizations: groups accounts into OUs (Organizational Units).
- Management account should have minimal workloads — used for governance only.
- Common OU structure: Root → Security OU, Infrastructure OU, Workloads OU, Sandbox OU.
- Each OU can have SCPs applied — they filter what IAM can do within member accounts.
- Separate accounts for: production, dev/test, logging, security tooling, network (Transit Gateway).

### Service Control Policies (SCPs)
- Apply to OUs or individual accounts. Restrict maximum permissions — they are not grants.
- Even the account root user is subject to SCPs.
- Common uses: deny leaving AWS Organizations, deny disabling CloudTrail, deny disabling GuardDuty,
  restrict to specific regions, prevent creation of IAM users (force SSO).
- `aws:RequestedRegion` condition key: restrict services to approved regions.
- SCPs are deny-by-default — you must explicitly allow at the OU level, then IAM handles grants.
- Know the difference: SCP limits what's possible, IAM policy controls what's permitted within that limit.

### AWS Security Services
- **GuardDuty**: threat detection, analyzes CloudTrail, VPC Flow Logs, DNS logs. ML-based anomaly detection.
  Finds things like: crypto mining, credential exfiltration, unusual API calls, port scanning from EC2.
- **CloudTrail**: audit log of all API calls. Management events (control plane) vs data events (S3/Lambda).
  Multi-region trail, log file validation, send to S3 + CloudWatch Logs.
- **Security Hub**: aggregates findings from GuardDuty, Inspector, Macie, IAM Analyzer, third-party tools.
  Runs CIS AWS Foundations benchmarks automatically.
- **AWS Config**: tracks resource configuration changes over time. Config Rules evaluate compliance.
  Remediation actions can auto-fix non-compliant resources.
- **Macie**: ML-based sensitive data discovery in S3. Finds PII, credentials, financial data.
- **Inspector**: vulnerability scanning for EC2 and container images. CVE-based.
- **IAM Access Analyzer**: identifies resources shared externally (S3 buckets, IAM roles, KMS keys).
- **VPC Flow Logs**: captures IP traffic metadata (not payload) at ENI, subnet, or VPC level.

### S3 Security
- Block Public Access settings: apply at account and bucket level. Account-level overrides bucket.
- Bucket policies vs ACLs: use bucket policies, ACLs are legacy.
- Encryption: SSE-S3 (AWS managed), SSE-KMS (customer managed keys), SSE-C (customer provided keys).
- Object lock: WORM (Write Once Read Many) — useful for compliance/audit log immutability.
- Presigned URLs: time-limited access without requiring AWS credentials.
- Misconfiguration: public ACL or bucket policy that allows `s3:GetObject` to `*` (everyone).

### EC2 & Compute Security
- Security Groups: stateful, instance-level. Inbound and outbound rules. Deny by default.
- CIS benchmarks for EC2 hardening: disable root SSH, use key pairs, patch regularly, remove unnecessary services.
- Instance metadata service (IMDS): v1 is vulnerable to SSRF — always enforce IMDSv2 (requires session token).
- User data scripts: run at launch — can be a vector if not controlled. Never put secrets in user data.
- Systems Manager (SSM) Session Manager: replace SSH access. No open port 22 required.

### VPCs & Network Segmentation
- VPC: isolated network within AWS. CIDR block defines IP range.
- Subnets: public (route to IGW), private (no direct internet), isolated (no internet at all).
- Internet Gateway (IGW): enables public internet access.
- NAT Gateway: allows private subnet instances to initiate outbound internet connections.
- Transit Gateway: hub-and-spoke model for connecting multiple VPCs and on-prem networks.
- VPC Peering: direct connection between two VPCs. Not transitive.
- PrivateLink: private connectivity to AWS services without traversing internet.
- Security Group vs NACL: SG = stateful + instance, NACL = stateless + subnet. Use both in layers.

---

## Identity & Access Management

The JD lists IAM Identity Center, SCPs, and identity management systems.

### IAM Fundamentals
- Principals: users, groups, roles, service accounts.
- Policies: identity-based (attached to principal), resource-based (attached to resource), SCPs, permission boundaries.
- Effect/Action/Resource/Condition: the four elements of every policy statement.
- Least privilege: grant only what's needed. Audit regularly. Remove unused.
- IAM Roles: no long-term credentials. Assume via STS (Security Token Service). Prefer over IAM users.
- Cross-account roles: allow principals in one account to assume roles in another.

### AWS IAM Identity Center (SSO)
- Centralizes access management across all AWS accounts in an Organization.
- Permission sets: collections of policies deployed to accounts. Mapped to groups in identity provider.
- Integrates with external IdPs (Okta, Azure AD) via SAML 2.0 or SCIM for provisioning.
- SCIM: automates user/group sync from IdP to Identity Center. Removes manual provisioning.
- Replaces the old model of creating IAM users in every account.
- Access Portal: single URL where users see all their assigned accounts and roles.

### LDAP / Active Directory
- LDAP: directory protocol. Used to query AD, OpenLDAP, etc.
- DN (Distinguished Name): unique identifier for an object. `CN=Blake,OU=Security,DC=company,DC=com`
- Used for: auth, group membership, service account management.
- LDAP injection: similar to SQLi — unsanitized input inserted into LDAP queries.

### RADIUS (see also Networking section)
- Authentication for network access. Common in VPN and Wi-Fi environments.
- Works with AD/LDAP as backend directory.
- 802.1X: port-based network access control. RADIUS is the auth backend.

### Secrets Management
- HashiCorp Vault: dynamic secrets, leases, audit logging. Secrets never stored in application config.
- AWS Secrets Manager: managed service. Auto-rotation for RDS, Redshift, etc.
- AWS SSM Parameter Store: simpler, cheaper. Use SecureString for sensitive values.
- Never put secrets in: environment variables (without encryption), S3 without KMS, CloudFormation templates, Git repos.
- Detect leaked secrets: git-secrets, truffleHog, GitHub secret scanning, Macie.

---

## Wiz / CNAPP / CSPM

Wiz is explicitly called out as preferred in the JD. Know it deeply, not just what it does, but how you made decisions within it.

### What Wiz Does
- CNAPP: Cloud Native Application Protection Platform. Combines CSPM, CWPP, CIEM, IaC scanning, CDR.
- CSPM (Cloud Security Posture Management): finds misconfigurations across cloud accounts.
- CWPP (Cloud Workload Protection Platform): protects running workloads — VMs, containers, serverless.
- CIEM (Cloud Infrastructure Entitlement Management): finds overly permissive identities and roles.
- Wiz Security Graph: maps relationships between cloud resources to find toxic combinations
  (e.g. public-facing VM + vulnerable OS + admin IAM role = critical risk path).
- Agentless scanning: no agent required. Uses cloud provider APIs and snapshot analysis.

### Wiz Key Concepts
- Projects: organizational units in Wiz that map to cloud accounts/subscriptions/folders.
- RBAC: role-based access control within Wiz. Custom roles control what users can see and do.
- Policies: define what Wiz should alert on. Built-in + custom. Can be IaC, runtime, or posture-based.
- Wiz Sensor: lightweight agent for runtime threat detection (Wiz Defend). Deployed to Kubernetes nodes.
- Wiz Defend: CDR (Cloud Detection and Response). Runtime threat detection using Sensor data.
- Wiz Code: scans IaC (Terraform, CloudFormation) and source code before deployment. Shift-left.
- Wiz Brokers: connect Wiz Code to private SCM environments (self-hosted GitHub/GitLab).

### Wiz in Terraform
- Wiz supports full Terraform management of: projects, RBAC roles, policies, integrations.
- Treat Wiz config as code: version controlled, peer reviewed, consistent across environments.
- Key resources: `wiz_project`, `wiz_user_role`, `wiz_automation_rule`, `wiz_cloud_config_rule`.
- Benefits: auditability, prevents config drift, enables rollback.

### Vulnerability Prioritization in Wiz
- Not all criticals are equal. Use context: is the resource internet-facing? Does it have a privileged role?
- Wiz Security Graph: prioritize findings that are part of an attack path.
- Factors: CVSS score + exploitability + cloud context + blast radius.
- Work with engineering teams on SLAs: critical = 24–72 hours, high = 7 days, medium = 30 days.
- Track remediation trends over time, not just point-in-time counts.

---

## Infrastructure & Containers

The JD mentions workload protection and the role might involve Kubernetes environments, even if not explicitly stated.

### Containers & Docker
- Container: isolated process using Linux namespaces and cgroups. Shares host kernel.
- Image: read-only template. Container is a running instance.
- Container escape: breaking out of container isolation to access host. Often via misconfiguration
  (privileged mode, mounted Docker socket, hostPID/hostNetwork).
- Never run containers as root. Use non-root user in Dockerfile.
- Image scanning: check for CVEs in base images and dependencies. Do this in CI/CD (shift-left).
- Distroless images: minimal attack surface — no shell, no package manager.

### Kubernetes Security
- Pod: smallest deployable unit. One or more containers.
- RBAC in Kubernetes: separate from AWS IAM. Controls what k8s API actions are allowed.
- Pod Security Standards (PSS): replaces PodSecurityPolicy. Defines Privileged, Baseline, Restricted profiles.
- Network Policies: controls pod-to-pod and pod-to-external traffic. Deny-all default is ideal.
- Secrets in k8s: base64 encoded by default — NOT encrypted. Use Secrets Manager or Vault integration.
- Service Accounts: identity for pods. Scope tightly. Use IAM Roles for Service Accounts (IRSA) in EKS.
- etcd: k8s data store. Must be encrypted at rest and access tightly controlled.
- Admission controllers: intercept API server requests. OPA/Gatekeeper enforces policy.
- EKS vs AKS vs GKE: managed control plane, but node security is customer responsibility in all cases.

### Wiz Sensor on Kubernetes
- Deploys as a DaemonSet — one pod per node.
- Captures runtime syscalls to detect malicious behavior: reverse shells, crypto miners, privilege escalation.
- Sends telemetry to Wiz for correlation with cloud context.
- Minimal performance overhead — eBPF-based in modern versions.

---

## Cryptography & TLS

The JD lists TLS, cryptographic systems, and RSA/SHA explicitly.

### Fundamentals
- Symmetric encryption: same key to encrypt and decrypt. Fast. AES-256 is the standard.
  Use cases: encrypting data at rest, bulk data transfer after key exchange.
- Asymmetric encryption: public/private key pair. Slower. RSA, ECDSA.
  Use cases: TLS handshake, certificate signing, SSH authentication.
- Hashing: one-way function. Same input always produces same output. Cannot be reversed.
  SHA-256, SHA-3 are current standards. MD5 and SHA-1 are broken — do not use.
  Use cases: integrity verification, password storage (with salt + bcrypt/Argon2).
- HMAC: hash-based message authentication code. Combines hashing with a secret key.
  Verifies both integrity and authenticity.

### TLS (Transport Layer Security)
- Encrypts data in transit. TLS 1.2 is minimum acceptable. TLS 1.3 is preferred.
- TLS 1.3 improvements: removes weak cipher suites, mandatory forward secrecy, faster handshake.
- TLS Handshake (TLS 1.2):
  1. Client Hello: supported cipher suites, TLS version, random nonce.
  2. Server Hello: chosen cipher suite, server certificate, random nonce.
  3. Client verifies server certificate against trusted CA.
  4. Key exchange (RSA or ECDH): establish pre-master secret.
  5. Both sides derive session keys. Switch to symmetric encryption.
  6. Finished messages verify handshake integrity.
- Certificate: binds a public key to an identity. Signed by a CA (Certificate Authority).
- Certificate chain: leaf cert → intermediate CA → root CA. Root CA is trusted by OS/browser.
- Common TLS misconfigurations: expired certs, self-signed certs in prod, TLS 1.0/1.1 still enabled,
  weak cipher suites (RC4, DES), missing HSTS header.
- mTLS (Mutual TLS): both client and server authenticate. Used in zero-trust, service mesh (Istio).
- Certificate pinning: app only accepts specific cert/public key. Prevents MITM but complicates rotation.

### PKI (Public Key Infrastructure)
- CA: issues and signs certificates. Root CA is the ultimate trust anchor.
- CRL (Certificate Revocation List): list of revoked certs. Polled periodically.
- OCSP (Online Certificate Status Protocol): real-time revocation checking. Faster than CRL.
- OCSP stapling: server fetches its own OCSP response and includes it in TLS handshake.

### AWS KMS
- Key Management Service: creates and manages encryption keys. Never exposes plaintext key material.
- CMK (Customer Managed Key): you control key policy, rotation, deletion.
- AWS Managed Key: AWS rotates automatically. Less control.
- Envelope encryption: data encrypted with a data key, data key encrypted with CMK.
  Only the encrypted data key is stored alongside the data.
- Key policies: resource-based policies on keys. Must explicitly grant access — KMS denies by default.
- CloudHSM: dedicated hardware security module. FIPS 140-2 Level 3. For compliance requirements.

---

## Threat Detection & SIEM

The JD mentions SIEM integration, anomaly detection, and machine learning for analysis.

### SIEM Fundamentals
- Security Information and Event Management: collects, correlates, and alerts on log data.
- Common SIEMs: Splunk, Microsoft Sentinel, Elastic SIEM, Chronicle (Google), Sumo Logic.
- Log sources for cloud: CloudTrail, VPC Flow Logs, GuardDuty findings, WAF logs, ALB access logs,
  CloudWatch Logs, S3 server access logs, Lambda logs.
- Correlation rules: define patterns that indicate suspicious activity across multiple log sources.
- Alert fatigue: too many false positives causes analysts to ignore alerts. Tune ruthlessly.

### Detection Logic
- What to detect in cloud environments:
  - Root account usage (should never happen day-to-day).
  - IAM access key creation outside approved process.
  - Security group or NACL rules changed to allow 0.0.0.0/0.
  - GuardDuty: high-severity findings (crypto mining, credential theft, unusual API patterns).
  - CloudTrail: `DeleteTrail`, `StopLogging`, `UpdateTrail` — attacker covering tracks.
  - S3: `PutBucketAcl` with public ACL, `GetObject` from unusual IP/geo.
  - EC2: instance launched in unusual region, unusual instance type, new security group rules.
  - Failed auth spikes: brute force indicators.
  - Unusual IAM activity: `AssumeRole` across accounts, new access keys, policy changes.

### MTTD / MTTR
- MTTD (Mean Time to Detect): time from incident start to detection. Reduce by improving coverage and tuning.
- MTTR (Mean Time to Respond): time from detection to containment/resolution. Reduce by automation and runbooks.
- Ways to improve MTTD: better log coverage, lower alert thresholds, threat hunting, canary tokens.
- Ways to improve MTTR: automated playbooks, clear IR runbooks, pre-approved remediation scripts.

### GuardDuty Deep Dive
- Finding types: UnauthorizedAccess, Recon, Trojan, CryptoCurrency, Backdoor, Impact, Exfiltration.
- Integrates with Security Hub and EventBridge for automated response.
- Trusted IP lists: suppress findings from known internal IPs.
- Threat intelligence: AWS-managed + custom threat lists.
- GuardDuty for EKS: analyzes Kubernetes audit logs for anomalous API activity.
- GuardDuty for S3: analyzes data plane events for unusual access patterns.

---

## Incident Response

The JD explicitly lists incident response as a duty. Have a real story ready.

### IR Phases
1. **Preparation**: runbooks, playbooks, contacts, tooling ready before an incident.
2. **Detection & Analysis**: identify the incident, scope it, determine severity.
3. **Containment**: stop the bleeding. Short-term (isolate instance) and long-term (patch root cause).
4. **Eradication**: remove the threat (malware, compromised credentials, backdoors).
5. **Recovery**: restore systems to normal operation. Validate before returning to prod.
6. **Post-Incident Review**: blameless. What happened, why, what changes prevent recurrence.

### Cloud IR Specifics
- Isolate compromised EC2: change security group to deny all inbound/outbound. Detach from ASG.
- Preserve evidence: snapshot the EBS volume before terminating. Capture memory if possible.
- Revoke compromised IAM credentials immediately: deactivate access key, invalidate sessions.
- Check CloudTrail: what did the compromised principal do? What did it access? When?
- Check for persistence: new IAM users, new access keys, new Lambda functions, new EC2 instances,
  CloudTrail disabled, GuardDuty disabled, new trusted SAML providers.
- Containment is not remediation — don't clean up until you understand what happened.

### IR Runbook Elements
- Clear trigger conditions (what does this runbook apply to?).
- Severity classification criteria.
- Escalation path and contact list.
- Step-by-step containment actions with AWS CLI commands ready.
- Evidence collection checklist.
- Communication templates (internal, legal, customer-facing if needed).
- Recovery validation steps.
- Post-incident review schedule.

### STAR Format for IR Stories
- **Situation**: what was the environment, what triggered the incident?
- **Task**: what was your role in the response?
- **Action**: what specific steps did you take?
- **Result**: what was the outcome? What improved afterward?

---

## Vulnerability Management

The JD lists vulnerability management and remediation recommendations explicitly.

### Vulnerability Lifecycle
1. Discovery: scanner (Wiz, Inspector, Nessus, Qualys) finds CVE or misconfiguration.
2. Assessment: severity scoring (CVSS), contextual risk (internet-facing? privileged?).
3. Prioritization: not all criticals are equal. Attack path context matters more than raw score.
4. Remediation: patch, mitigate, or accept with documented rationale.
5. Verification: rescan to confirm fix. Track closure time for reporting.

### CVSS (Common Vulnerability Scoring System)
- Score 0–10. Critical = 9.0–10.0, High = 7.0–8.9, Medium = 4.0–6.9, Low = 0.1–3.9.
- Base score factors: attack vector, attack complexity, privileges required, user interaction,
  confidentiality/integrity/availability impact.
- Base score alone is not enough — add temporal (is there a public exploit?) and
  environmental (does this asset matter to you?) context.
- EPSS (Exploit Prediction Scoring System): probability a CVE will be exploited in the wild.
  Use alongside CVSS for better prioritization.

### Remediation SLAs
- Define and enforce SLAs: Critical = 24–72 hrs, High = 7 days, Medium = 30 days, Low = 90 days.
- Track exceptions: document accepted risk with business justification and review date.
- Patch management: AMI pipelines bake patches in. Auto-patching via Systems Manager Patch Manager.
- Container images: rebuild and redeploy — patching running containers is not a durable fix.

---

## Threat Modeling

The JD mentions architecture reviews and secure-by-design. Threat modeling is the process behind both.

### STRIDE Framework
- **S**poofing: impersonating a user or service. Mitigation: authentication.
- **T**ampering: modifying data or code. Mitigation: integrity controls, signing.
- **R**epudiation: denying an action occurred. Mitigation: audit logging, non-repudiation.
- **I**nformation Disclosure: unauthorized access to data. Mitigation: encryption, access control.
- **D**enial of Service: making a service unavailable. Mitigation: rate limiting, redundancy.
- **E**levation of Privilege: gaining more access than permitted. Mitigation: least privilege, RBAC.

### Threat Modeling Process
1. Define scope: what system are we modeling? Draw a data flow diagram.
2. Identify assets: what are we protecting? Data, services, credentials, reputation.
3. Identify threats: use STRIDE or attack tree methodology.
4. Identify mitigations: what controls exist? What's missing?
5. Prioritize: likelihood × impact. Focus effort where risk is highest.
6. Document and track: open items become tickets. Revisit when system changes.

### Trust Boundaries
- Draw them wherever data crosses a trust level: internet → DMZ, DMZ → internal, user → admin.
- Every data flow crossing a trust boundary is a potential threat vector.
- In AWS: account boundaries, VPC boundaries, IAM role boundaries, public-facing endpoints.

### Secure by Design Principles
- Least privilege by default — deny all, grant explicitly.
- Defense in depth — multiple independent layers of control.
- Fail secure — if a control fails, the system should default to the more secure state.
- Minimize attack surface — disable unused services, close unused ports, remove unused IAM permissions.
- Don't trust input — validate and sanitize at every trust boundary.

---

## Compliance & Governance

The JD mentions PCI DSS, compliance governance, and internal controls.

### PCI DSS
- Payment Card Industry Data Security Standard. 12 requirements across 6 goals.
- Goal 1 (Build secure network): firewalls, no vendor defaults.
- Goal 2 (Protect cardholder data): encryption, data minimization.
- Goal 3 (Vulnerability management): AV, patches, secure development.
- Goal 4 (Access control): need-to-know, unique IDs, physical access.
- Goal 5 (Monitor and test): logging, IDS, penetration testing.
- Goal 6 (Security policy): documented policy, training.
- In AWS: use dedicated account for CDE (Cardholder Data Environment). Isolate with VPC, SCPs.
  CloudTrail + CloudWatch for logging requirement. Config Rules for continuous compliance.

### CIS Benchmarks
- Center for Internet Security: prescriptive hardening guides for AWS, Linux, Windows, containers.
- CIS AWS Foundations Benchmark: covers IAM, logging, monitoring, networking. Security Hub automates checks.
- Use as a baseline — understand why each control exists, not just that it's required.

### Audit & Evidence Collection
- CloudTrail: API-level audit log. Enable multi-region, log file validation, send to immutable S3.
- Config: resource configuration history. Proves what a resource looked like at a point in time.
- Access logs: S3, ALB, CloudFront, API Gateway. Show who accessed what and when.
- Retention: define retention periods per data type. Legal hold process for active investigations.
- Immutability: S3 Object Lock (WORM), CloudTrail log file validation to detect tampering.

---

## Python & Scripting

The JD requires Python/scripting experience. Use Lambda/Step Functions work as evidence.

### Python Essentials for Cloud Security
- Boto3: AWS SDK for Python. Used for everything — querying, remediating, automating.
- Common patterns:
  ```python
  import boto3

  # List all S3 buckets
  s3 = boto3.client('s3')
  buckets = s3.list_buckets()['Buckets']

  # Check public access block
  for bucket in buckets:
      try:
          config = s3.get_public_access_block(Bucket=bucket['Name'])
          pab = config['PublicAccessBlockConfiguration']
          if not all(pab.values()):
              print(f"WARNING: {bucket['Name']} has public access enabled")
      except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
          print(f"WARNING: {bucket['Name']} has no public access block configured")
  ```

- Paginator pattern (always use for large result sets):
  ```python
  paginator = boto3.client('iam').get_paginator('list_users')
  for page in paginator.paginate():
      for user in page['Users']:
          print(user['UserName'])
  ```

- Assume role across accounts:
  ```python
  sts = boto3.client('sts')
  creds = sts.assume_role(
      RoleArn='arn:aws:iam::123456789:role/SecurityAuditRole',
      RoleSessionName='audit-session'
  )['Credentials']

  session = boto3.Session(
      aws_access_key_id=creds['AccessKeyId'],
      aws_secret_access_key=creds['SecretAccessKey'],
      aws_session_token=creds['SessionToken']
  )
  ```

### Lambda & Step Functions
- Lambda: serverless function. Event-driven. Max 15 min execution. No persistent state.
- Error handling in Lambda: try/except + dead letter queue (SQS/SNS) for failed invocations.
- Step Functions: orchestrates Lambda functions as a state machine. Handles retries, parallel execution,
  branching logic, error handling at the workflow level.
- State types: Task (invoke Lambda), Choice (branching), Wait (pause), Parallel (concurrent paths),
  Map (iterate over list), Pass (pass data through), Fail/Succeed.
- Use Step Functions when: workflow has multiple steps, needs retry logic, has parallel paths,
  needs human approval steps, or execution time exceeds Lambda limit.

### JSON & Log Parsing
- CloudTrail log entries are JSON. Know how to navigate nested structures.
  ```python
  import json

  with open('cloudtrail.json') as f:
      log = json.load(f)

  for record in log['Records']:
      if record['eventName'] == 'DeleteTrail':
          print(f"ALERT: Trail deleted by {record['userIdentity']['arn']} at {record['eventTime']}")
  ```

- Useful patterns: filter by eventName, userIdentity, sourceIPAddress, errorCode.
- `errorCode` present = failed API call. Track failed `AssumeRole`, `GetSecretValue`, `Decrypt` calls.

---

## Security Themed Coding Challenges

Practice these — they reflect realistic security engineering automation tasks.

- Write a script that lists all IAM users in an account and flags any without MFA enabled.
- Write a script that checks all EC2 security groups for rules that allow 0.0.0.0/0 inbound on sensitive ports.
- Write a Lambda function that auto-remediates an S3 bucket made public (triggered by Config rule or EventBridge).
- Write a script that cross-account assumes a read-only role in every account in your AWS Organization and pulls GuardDuty finding counts.
- Write a Python function that parses a CloudTrail log file and extracts all `AssumeRole` events with cross-account targets.
- Write a script that checks all RDS instances for encryption at rest and public accessibility.
- Given a Wiz finding in JSON format, parse it and output a formatted summary: resource, severity, issue, recommended fix.
- Write a script that lists all S3 buckets without server-side encryption enabled.
- Implement a simple retry wrapper for Boto3 calls that handles `ThrottlingException` with exponential backoff.

---
