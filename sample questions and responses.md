# Nintendo Cloud Security Engineer – Interview Study Guide
*(Based on my resume + Nintendo JD + AI‑security add‑ons)*

## 1. Cloud Security Architecture & Standards

**Core Question 1**  
“Walk me through how you’ve helped define or improve cloud security architecture and standards.”

- Context  
  - Multi‑cloud at Sony Interactive Entertainment (SIE): 1,000+ AWS, Azure, GCP accounts.  
  - Focus on secure‑by‑design architectures and policy‑driven guardrails.

- Architecture & governance  
  - Designed security architectures with secure configuration baselines.  
  - Created and maintained Service Control Policies (SCPs) for multiple OUs (PSN + enterprise).  
  - Built a source‑of‑truth IaC repo (CloudFormation + Terraform) for all AWS accounts.  
  - Automated cloud account provisioning via CloudFormation → later migrated to Terraform.

- Shift‑left & standards  
  - Partnered with Global Security Architecture / GRC to embed standards (logging, IAM patterns, segmentation).  
  - Worked with first‑party studios to deploy Wiz Code into dev environments to catch issues early.

- Nintendo tie‑in  
  - Directly aligns with partnering with a Cloud Platform team to embed secure‑by‑design patterns and standards.

---

## 2. CNAPP, Wiz, and Cloud Security Tooling

**Core Question 2**  
“What’s your experience with cloud security tooling like Wiz or similar CNAPP/CSPM platforms?”

- Wiz ownership  
  - Deployed and managed Wiz Sensor across EKS, AKS, and GKE.  
  - Managed Wiz CNAPP configuration (projects, RBAC, policies) fully in Terraform.

- Wiz Code and shift‑left  
  - Connected Wiz Code to studio environments / CI pipelines.  
  - Tuned policies to match Sony Security Standards and reduce noise.

- Detection & SOC integration  
  - Collaborated with SOC/IR to tune Wiz Defend detections.  
  - Improved MTTD/MTTR by focusing on high‑value alerts and reducing false positives.  
  - Used PrismaCloud, GuardDuty, McAfee DAM, CloudPassage for posture and threat detection.

- Nintendo tie‑in  
  - JD calls out AWS and Wiz; I bring hands‑on, large‑scale experience with both.

---

## 3. Risk Assessments & Vulnerability Management

**Core Question 3**  
“How do you approach risk assessments and security reviews for cloud workloads?”

- Information gathering  
  - Understand system purpose, data classification (PII/PCI/internal), business criticality.  
  - Review architecture diagrams, data flows, and compliance scope (e.g., PCI DSS).

- Technical assessment  
  - IAM design (roles, policies, trust, privilege).  
  - Network exposure: VPCs, subnets, SGs, WAF, internet‑facing endpoints.  
  - CNAPP (Wiz/PrismaCloud) + native tools (GuardDuty) to find misconfigs and vulns.

- Risk analysis  
  - Prioritize based on exploitability, impact, blast radius.  
  - Map findings to internal standards and external requirements (e.g., PCI controls).

- Recommendations & follow‑through  
  - Concrete changes: SCP tightening, segmentation, IAM least privilege, WAF rules, encryption.  
  - Track remediation; validate via IaC changes and rescans.

---

## 4. Logging, Monitoring, SIEM & Detection

**Core Question 4**  
“Tell me about integrating cloud environments with a SIEM and building detections.”

- Logging baseline  
  - Org‑wide, multi‑region CloudTrail.  
  - VPC Flow Logs, load balancer logs, Kubernetes audit logs, key service logs (e.g., RDS).  

- Centralization  
  - Forward logs and alerts to SIEM (e.g., Splunk) through centralized pipelines.  
  - Normalize formats and enforce tagging for correlation.

- Detections  
  - Suspicious IAM changes and role assumptions.  
  - Network anomalies and unusual traffic patterns.  
  - High‑severity CNAPP findings (Wiz/PrismaCloud) and GuardDuty alerts.  
  - WAF events from Akamai Kona / Imperva (SQLi, XSS, brute‑force, DDoS).

- Tuning & MTTD/MTTR  
  - Work closely with SOC to tune out noise.  
  - Maintain runbooks for high‑priority alerts to speed triage and response.

---

## 5. Incident Response in Cloud

**Core Question 5**  
“Describe a complex security incident you handled in the cloud and your role.”

- Example incident pattern  
  - GuardDuty / SIEM flags anomalous AWS API usage from unusual IP/region.  
  - Identity involved is a specific IAM role or user.

- Containment  
  - Disable or rotate credentials.  
  - Apply restrictive SCPs / IAM changes to limit blast radius.  
  - Block attacker IPs at WAF / security groups if applicable.

- Investigation  
  - Use CloudTrail to reconstruct attacker actions.  
  - Correlate with Wiz/PrismaCloud/GuardDuty findings.  
  - Assess data access/changes on key resources (S3, IAM, EC2, RDS, etc.).

- Eradication & recovery  
  - Remove any backdoors or malicious IAM/policy changes.  
  - Harden IAM, rotate secrets (Vault/CyberArk/AWS Secrets Manager).  

- Lessons learned  
  - New or improved detections.  
  - Stronger guardrails in IaC and SCPs to prevent recurrence.

---

## 6. Network Security, WAF, and Topologies

**Core Question 6**  
“How does your networking background help you secure cloud workloads?”

- Traditional networking base  
  - Experience at QuadraNet and DIRECTV with VLANs, routing, Cisco/Juniper, VPNs, DNS/DHCP.  
  - LAMP/webserver management, media streaming, and data center operations.

- Cloud network design  
  - VPCs with segmented subnets (public/private).  
  - Security groups and NACLs with least privilege.  
  - Centralized egress patterns and restricted admin access.

- WAF & edge  
  - Administered Akamai Kona and Imperva for DDoS, SQLi, XSS, brute‑force mitigation.  
  - Tuned WAF rules based on real traffic and app behavior.  
  - Fed WAF logs into SIEM for detection and analytics.

- Nintendo tie‑in  
  - Strong understanding of TCP/IP, HTTP, DNS, TLS, firewalls, IDS/IPS fits JD requirements.

---

## 7. IAM & Least Privilege

**Core Question 7**  
“How do you design AWS IAM for least privilege at scale?”

- Principles & patterns  
  - Role‑based access via AWS IAM Identity Center.  
  - Separate roles for admin, operator, read‑only, CI/CD, and break‑glass.  
  - Prefer roles for workloads, avoid long‑lived keys.

- Implementation  
  - Start restrictive and add specific permissions as needed.  
  - Use conditions (tags, IP ranges, MFA) where useful.  

- Governance  
  - Enforce IAM through Terraform/CloudFormation templates in a central repo.  
  - Periodic reviews with tooling (IAM Access Analyzer / CNAPP features).

- Monitoring  
  - Log key IAM events and send to SIEM.  
  - Add detections for risky activity (policy changes, new keys, privilege escalation).

---

## 8. Automation, Scripting & CI/CD Security

**Core Question 8**  
“How have you used automation and scripting to improve security?”

- IaC and account provisioning  
  - Architected a fully automated AWS account provisioning process (CloudFormation → Terraform).  
  - Baselines include logging, guardrails, and IAM standards from day one.

- Scripting (Bash/Python)  
  - Automations for:  
    - Deploying IAM roles across accounts.  
    - Running bulk SCP updates.  
    - Updating Wiz configuration via Terraform pipelines.

- CI/CD security  
  - Automated deployments via Jenkins + Ansible + AWS Config + CloudFormation.  
  - Integrated security checks into pipelines (image scanning, config checks, IaC validation).

---

## 9. Behavioral & Collaboration

**Core Question 9**  
“Tell me about a time you partnered with engineers to roll out a security initiative.”

- Scenario: Wiz Code with first‑party studios  
  - Studio concern: extra noise and developer friction.  
  - Approach:  
    - Met with leads to map pipelines and pain points.  
    - Piloted Wiz Code with tuned policies and clear documentation.  
    - Integrated results into existing tools (e.g., PR checks, dashboards).  
  - Outcome: fewer production issues, better perception of security as an enabler.

---

## 10. AI / ML Security – General Cloud AI Workloads

**AI Question 1**  
“How would you secure an AI/ML workload running in the cloud?”

- Understand the workload  
  - Identify sensitive data types and regulatory scope.  
  - Clarify training vs. inference environment and exposure.

- Environment & network  
  - Isolated VPCs / namespaces for training and inference.  
  - Strict SGs/network policies, private endpoints for data access.

- IAM & data protection  
  - Least‑privilege roles for training/inference jobs.  
  - Encrypt datasets and model artifacts in transit and at rest (KMS).

- Monitoring & CNAPP  
  - Use Wiz/PrismaCloud on the Kubernetes/GPU infra.  
  - Centralize logs (API gateway, model server, data access) into SIEM.

---

## 11. AI / ML Security – Data & Model Risks

**AI Question 2**  
“What are the main security risks around AI models and training data?”

- Training data  
  - Sensitive data accidentally included.  
  - Misconfigured storage exposing data.

- Model & IP  
  - Theft of model artifacts; extraction via APIs.  

- Abuse & supply chain  
  - Abuse of inference APIs (scraping, brute‑forcing).  
  - Tampered images, libraries, or base models in the pipeline.

- Mitigations  
  - Strong IAM, encryption, segmentation; WAF in front of inference APIs.  
  - CNAPP scanning; IaC guardrails; robust logging and SIEM detections.

---

## 12. LLM / Prompt‑Injection & Internal Assistants

**AI Question 3**  
“If Nintendo used an internal LLM for engineers, what security concerns would you have?”

- Prompt injection & untrusted output  
  - Treat LLM output as untrusted.  
  - Do not let it directly perform privileged actions.

- Data leakage  
  - Sensitive code/credentials pasted into prompts.  
  - Need classification policies, redaction, DLP on logs.

- Access & monitoring  
  - SSO and RBAC for LLM access; detailed usage logging.  
  - SIEM detections for suspicious prompt patterns (e.g., trying to extract secrets).

- Integration boundaries  
  - LLM suggests actions; humans approve via standard change process.  

---

## 13. Third‑Party AI / LLM SaaS

**AI Question 4**  
“How would you evaluate using a third‑party AI/ML SaaS with company data?”

- Policy & data classification  
  - What classes of data can be sent? Which are prohibited?  

- Vendor review  
  - Data retention and training behavior.  
  - Encryption, key management, data residency.

- Integration  
  - Use secrets managers for API keys.  
  - Route traffic through controlled egress; log all usage.

---

## 14. AI in Player‑Facing / In‑Game Features

**AI Question 5**  
“If Nintendo used AI for player experiences, what security issues would you watch for?”

- Abuse scenarios  
  - Gaming recommendations/matchmaking; bot exploitation.  

- Data integrity & privacy  
  - Protect telemetry and training inputs.  
  - Ensure compliance with regional privacy requirements.

- Infrastructure  
  - Secure inference APIs with auth, WAF, rate limits.  
  - Monitor with SIEM + CNAPP.

---

## 15. AI for Security Operations

**AI Question 6**  
“How would you safely use AI to help with security operations?”

- Use cases  
  - Triage assistance, log summarization, correlation suggestions.  
  - Not autonomous production changes.

- Data controls  
  - Redact secrets and sensitive fields before analysis.  
  - Keep data within approved boundaries (internal models or vetted SaaS).

- Guardrails  
  - Human in the loop; standard change‑management for any remediation.  
  - Log AI suggestions and analyst decisions for feedback and improvement.
