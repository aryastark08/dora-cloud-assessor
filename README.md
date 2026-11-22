# DORA Cloud Compliance Assessor

Automated assessment of AWS environments against **DORA** (Regulation (EU) 2022/2554), producing a client-style report that maps every technical misconfiguration to the DORA article it engages, the relevant **ISO/IEC 27001:2022** Annex A controls and the **CIS AWS Foundations Benchmark**.

📄 My **[Sample report](report/assessment-report.pdf)**, assessing a fictional Luxembourg fund administrator.

---

## The problem

Cloud security tools describe findings in technical terms: *this bucket has Block Public Access disabled*. Financial regulation describes obligations in different terms: *financial entities shall implement policies that limit access to information assets*. Both describe the same issue, and translating between them is usually done by hand: slowly, and inconsistently from one assessor to the next.

This project automates that translation for AWS environments subject to DORA.

---

## How it works

```
 Terraform lab ──► scanner.py ──► findings.json ──► report.py ──► assessment-report.pdf
                       │
                  mappings.py   (DORA · ISO 27001 · CIS · risk scoring · owners)
```

| Component | Role |
|---|---|
| `terraform/` | Deliberately misconfigured AWS environment for testing |
| `scanner/scanner.py` | Read-only API checks. Reports **what** is wrong, nothing more |
| `scanner/mappings.py` | The control mapping table. Defines what each finding **means** |
| `scanner/report.py` | Renders findings into a PDF assessment report |
| `engagement.json` | Entity and engagement details for the report |
| `accepted_risks.json` | Formally accepted risks, with justification and review date |
| `tests/run_mock.py` | Runs the whole pipeline against a simulated account, no AWS needed |

---

## Checks

| ID | Finding | DORA | ISO 27001:2022 |
|---|---|---|---|
| `AWS-EC2-001` | Security group allows administrative access (SSH/RDP) from the internet | Art. 9 | A.8.20, A.8.22 |
| `AWS-IAM-001` | IAM user holds full administrative privileges | Art. 9 | A.8.2, A.5.15 |
| `AWS-IAM-002` | IAM user with console access has no MFA | Art. 9 | A.8.5 |
| `AWS-S3-001` | S3 Block Public Access settings disabled | Art. 9 | A.8.3, A.8.9 |
| `AWS-EBS-001` | EBS volume not encrypted at rest | Art. 9 | A.8.24 |
| `AWS-CT-001` | No active CloudTrail trail logging in region | Art. 10 | A.8.15, A.8.16 |
| `AWS-S3-002` | S3 bucket versioning not enabled | Art. 12 | A.8.13 |

Risk is scored as **likelihood × impact** (1–5 each): 20–25 Critical, 12–19 High, 6–11 Medium, 1–5 Low.

---

## Design decisions

**Detection is separate from interpretation.** Checks report facts; `mappings.py` decides what they mean. Every regulatory mapping can be reviewed and challenged in one file without reading detection code.

**Weakened controls are distinguished from realised exposure.** Disabling Block Public Access does not make a bucket public: it removes the guardrail that prevents it. The report says so, and scores partial disablement lower than full.

**Compounding risk is scored, not just listed.** An administrator without MFA is materially worse than either condition alone, so impact is raised when both apply.

**MFA findings follow CIS scope.** The control applies to users who can sign in to the console. A user with no password cannot be phished for one.

**No hardcoded exclusions.** The operator's own admin account is reported like any other. Known risks are recorded as **documented acceptances** with justification, compensating controls and a review date. Suppressing a detection hides a risk; accepting one records a decision.

**Residual risk is not automated.** It depends on compensating controls that a configuration review cannot observe, so it is left to the risk owner.

**Account identifiers are redacted by default.** They are useful reconnaissance material.

---

## Usage

```bash
pip install -r requirements.txt
```

**Without an AWS account** (simulated with moto):

```bash
pip install -r requirements-dev.txt
python3 tests/run_mock.py
cd scanner && python3 report.py --findings ../tests/findings.json
```

**Against a real account:**

```bash
cd terraform && terraform init && terraform apply      # build the lab
cd ../scanner
python3 scanner.py                                     # -> findings.json
python3 report.py                                      # -> report/assessment-report.pdf
cd ../terraform && terraform destroy                   # tear it down
```

> ⚠️ The Terraform configuration creates **intentionally insecure resources**. Use a dedicated test account only, and destroy it when you're done.

The scanner needs read-only permissions, for example the AWS-managed `SecurityAudit` policy.

---

## Scope and limitations

- Covers the parts of DORA **Chapter II** that can be evidenced from cloud configuration (Articles 9, 10, 12). Governance and process obligations (Articles 5–8, 11, 13–14) need document review and interviews.
- IAM analysis covers **directly attached managed policies**. Permissions inherited through groups or granted by inline policies are not evaluated.
- One region per run, plus global IAM.
- A configuration review, not a penetration test or a formal audit.

---

## Roadmap

- [x] Scanner with seven finding types
- [x] DORA, ISO 27001 and CIS mapping table
- [x] Inherent risk scoring with compounding
- [x] PDF report generation
- [x] Documented risk acceptances
- [x] Account identifier redaction
- [ ] Group and inline IAM policy analysis
- [ ] Multi-region scanning
- [ ] Azure equivalent

---

## Author

**Aishwarya Jeevan Nair**, Erasmus Mundus Master's in Cybersecurity, University of Luxembourg.

Corrections are welcome, particularly on the regulatory mappings.

## Licence

MIT
