"""
Control mapping table: the core of the project.

Each check in scanner.py reports only WHAT it found. Everything about what that
finding MEANS (which regulation it engages, which controls it breaches, how
risky it is, who should fix it) lives here, in one auditable place.

Changing a mapping never requires touching detection code, and a reviewer can
challenge every mapping decision by reading this file alone.

Sources
-------
DORA       Regulation (EU) 2022/2554, Chapter II (Articles 5-16)
ISO 27001  ISO/IEC 27001:2022, Annex A
CIS        CIS Amazon Web Services Foundations Benchmark v7.1.0
           (IDs verified against the v7.1.0 PDF; numbering changes between
           versions, so re-verify if the benchmark version changes)

Risk scoring
------------
Inherent risk = likelihood (1-5) x impact (1-5), before any compensating
controls. Residual risk is NOT scored automatically: it depends on controls a
scanner cannot see, so it is left to the risk owner.

Likelihood
  1  Rare: needs several unlikely steps or a highly privileged insider
  2  Unlikely: needs existing account access plus specific conditions
  3  Possible: one further event, accidental or deliberate, that nothing prevents
  4  Likely: directly exploitable with modest effort, e.g. phishing a password
  5  Almost certain: exposed to the internet now and routinely scanned

Impact
  1  Negligible
  2  Minor: non-sensitive data or a non-critical system
  3  Moderate: data readable only by those with existing access, or loss of
     recoverability
  4  Major: disclosure of client or personal data; regulatory notification likely
  5  Severe: full control of the account or critical services

Impact assumes the entity context in engagement.json (a fund administrator
holding client data). The scanner cannot see data classification, so impact for
storage findings reflects the most plausible sensitivity, not a confirmed one.

Rating bands: 20-25 Critical, 12-19 High, 6-11 Medium, 1-5 Low.
"""

DORA_ARTICLES = {
    "Art. 9": "Protection and prevention",
    "Art. 10": "Detection",
    "Art. 12": "Backup policies and procedures, restoration and recovery",
}

RATING_BANDS = [  # (minimum score, rating)
    (20, "Critical"),
    (12, "High"),
    (6, "Medium"),
    (1, "Low"),
]


def rating_for(score: int) -> str:
    for minimum, rating in RATING_BANDS:
        if score >= minimum:
            return rating
    return "Low"


CONTROLS = {
    "AWS-S3-001": {
        "risk_statement": "Any change to the bucket's access settings could expose its contents publicly, with nothing in place to stop it.",
        "title": "S3 Block Public Access settings disabled",
        "dora": "Art. 9",
        "iso": ["A.8.3 Information access restriction", "A.8.9 Configuration management"],
        "cis_title": "Ensure that S3 is configured with 'Block Public Access' enabled",
        "cis_id": "3.1.4",
        "likelihood": 3,
        "impact": 4,
        "effort": "Low",
        "owner": "Cloud Operations",
        "remediation": (
            "Enable all four Block Public Access settings on the bucket, and at "
            "account level so new buckets inherit them."
        ),
    },
    "AWS-S3-002": {
        "risk_statement": "Data deleted or overwritten in error, or encrypted by ransomware, could not be restored from the bucket.",
        "title": "S3 bucket versioning not enabled",
        "dora": "Art. 12",
        "iso": ["A.8.13 Information backup"],
        "cis_title": "No direct control. Related: CIS 3.1.2 (MFA Delete), which requires versioning as a prerequisite",
        "cis_id": "",
        "likelihood": 3,
        "impact": 3,
        "effort": "Low",
        "owner": "Cloud Operations",
        "remediation": (
            "Enable versioning so overwritten or deleted objects can be restored, "
            "and add lifecycle rules to control storage cost."
        ),
    },
    "AWS-EC2-001": {
        "risk_statement": "Any host on the internet can attempt to log in to servers in this group, one of the most common entry points for attackers.",
        "title": "Security group allows administrative access from the internet",
        "dora": "Art. 9",
        "iso": ["A.8.20 Networks security", "A.8.22 Segregation of networks"],
        "cis_title": (
            "Ensure no security groups allow ingress from 0.0.0.0/0 (6.3) or ::/0 (6.4) "
            "to remote server administration ports"
        ),
        "cis_id": "6.3 / 6.4",
        "likelihood": 5,
        "impact": 4,
        "effort": "Low",
        "owner": "Network / Cloud Operations",
        "remediation": (
            "Remove the 0.0.0.0/0 rule. Restrict administrative access to known "
            "ranges, or replace SSH exposure with AWS Systems Manager Session Manager."
        ),
    },
    "AWS-IAM-001": {
        "risk_statement": "Compromise of this user's credentials would give an attacker complete control of the cloud account.",
        "title": "IAM user holds full administrative privileges",
        "dora": "Art. 9",
        "iso": ["A.8.2 Privileged access rights", "A.5.15 Access control"],
        "cis_title": (
            "Ensure IAM policies that allow full \"*:*\" administrative "
            "privileges are not attached"
        ),
        "cis_id": "2.14",
        "likelihood": 3,
        "impact": 5,
        "effort": "Medium",
        "owner": "Identity & Access Management",
        "remediation": (
            "Replace AdministratorAccess with a least-privilege policy scoped to "
            "the user's duties. Grant permissions through groups or roles rather "
            "than directly to users."
        ),
    },
    "AWS-IAM-002": {
        "risk_statement": "A single stolen or guessed password is enough to sign in to the console.",
        "title": "IAM user with console access has no MFA",
        "dora": "Art. 9",
        "iso": ["A.8.5 Secure authentication"],
        "cis_title": (
            "Ensure multi-factor authentication (MFA) is enabled for all IAM "
            "users that have a console password"
        ),
        "cis_id": "2.10",
        "likelihood": 4,
        "impact": 4,   # raised to 5 by the scanner when the user is also an administrator
        "effort": "Low",
        "owner": "Identity & Access Management",
        "remediation": "Enrol a virtual or hardware MFA device for this user.",
    },
    "AWS-EBS-001": {
        "risk_statement": "Data on this volume, and on any snapshot taken of it, is stored in readable form.",
        "title": "EBS volume not encrypted at rest",
        "dora": "Art. 9",
        "iso": ["A.8.24 Use of cryptography"],
        "cis_title": "Ensure EBS volume encryption is enabled in all regions",
        "cis_id": "6.1.1",
        "likelihood": 2,
        "impact": 3,
        "effort": "Medium",
        "owner": "Cloud Operations",
        "remediation": (
            "Enable EBS encryption by default for the region. Migrate existing "
            "volumes by snapshotting, copying the snapshot with encryption, and "
            "restoring."
        ),
    },
    "AWS-CT-001": {
        "risk_statement": "Malicious or accidental changes would leave no reliable record, hindering detection and investigation.",
        "title": "No active CloudTrail trail logging in region",
        "dora": "Art. 10",
        "iso": ["A.8.15 Logging", "A.8.16 Monitoring activities"],
        "cis_title": "Ensure CloudTrail is enabled in all regions",
        "cis_id": "4.1",
        "likelihood": 4,
        "impact": 4,
        "effort": "Low",
        "owner": "Security Operations",
        "remediation": (
            "Create a multi-region trail with log file validation, delivering to "
            "a dedicated, access-restricted S3 bucket."
        ),
    },
}
