# DORA Cloud Compliance Assessor

Automated assessment of AWS environments against **DORA** (Regulation (EU) 2022/2554), mapping technical misconfigurations to the specific regulatory articles and ISO 27001 controls they engage.


---

## The problem

Cloud security tooling reports findings in technical terms: a storage bucket is publicly accessible, a volume is unencrypted. European financial regulation states obligations in different language: entities must implement policies ensuring the protection of data at rest and in transit.

Both describe the same issue. Translating between them is manual, slow, and inconsistent between the people doing it.

This project automates that translation for AWS environments subject to DORA.

---

## What it does

| Component | Description |
|---|---|
| **Lab environment** | Terraform configuration provisioning a deliberately misconfigured AWS environment for testing |
| **Scanner** | Python/boto3 checks returning structured findings with regulatory mappings |
| **Report generator** | *(in development)* Client-grade PDF assessment report |

---

## Current checks

| ID | Finding | DORA Article |
|---|---|---|
| `AWS-S3-001` | S3 Block Public Access settings disabled | Art. 9 — Protection and prevention |
| `AWS-EC2-001` | Security group permits ingress from `0.0.0.0/0` | Art. 9 — Protection and prevention |
| `AWS-IAM-001` | IAM user holds full administrative privileges | Art. 9 — Protection and prevention |
| `AWS-IAM-002` | IAM user has no MFA device enrolled | Art. 9 — Protection and prevention |
| `AWS-EBS-001` | EBS volume unencrypted at rest | Art. 9 — Protection and prevention |

CIS AWS Foundations Benchmark and ISO 27001 Annex A mappings are being populated.

---

## Design notes

**Weakened controls are reported separately from realised exposure.** Disabling S3 Block Public Access does not make a bucket public — it removes the guardrail preventing it. These are different risks warranting different severity, and most scanners conflate them.

**No hardcoded exclusions.** Findings against the operator's own administrative account are reported rather than suppressed. Known risks belong in a risk register as documented acceptances, not hidden from the scan.

---

## Usage

**Prerequisites:** Python 3.9+, `boto3`, Terraform ≥ 1.5, AWS credentials with read access.

```bash
# Provision the lab environment
cd terraform
terraform init
terraform apply

# Run the assessment
cd ../scanner
python3 scanner.py

# Tear down
cd ../terraform
terraform destroy
```

> The Terraform configuration creates **intentionally insecure resources**. Deploy only to a dedicated test account, and destroy when not in use.

---

## Scope and limitations

- Covers DORA **Chapter II** (ICT risk management framework) only
- IAM checks evaluate **directly attached managed policies**; permissions inherited via group membership or granted through inline policies are not assessed
- Not a substitute for a formal audit or a comprehensive security assessment

---

## Roadmap

- [ ] CIS Benchmark and ISO 27001 control mappings
- [ ] Risk scoring (inherent and residual)
- [ ] PDF report generation
- [ ] CloudTrail and backup configuration checks
- [ ] Account identifier redaction

---

## Author

Built by **Aishwarya Nair** as a self-directed project.

Corrections and suggestions welcome — particularly on the regulatory mappings.

---

## Licence

MIT
