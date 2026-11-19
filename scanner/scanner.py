"""
DORA Cloud Compliance Assessor — AWS scanner
Maps AWS misconfigurations to DORA articles and ISO 27001 controls.
"""

import json
from dataclasses import dataclass, asdict, field

import boto3


@dataclass
class Finding:
    finding_id: str
    title: str
    resource: str
    severity: str          # Critical | High | Medium | Low
    cis_control: str
    iso_27001: str
    dora_article: str
    description: str
    remediation: str


# ---------------------------------------------------------------
# CHECK 1 — S3 Block Public Access
# ---------------------------------------------------------------

def check_s3_public_access(session) -> list[Finding]:
    s3 = session.client("s3")
    findings = []

    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except s3.exceptions.ClientError:
            # No configuration at all = no protection
            cfg = {k: False for k in (
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets")}

        disabled = [k for k, v in cfg.items() if not v]
        if disabled:
            findings.append(Finding(
                finding_id="AWS-S3-001",
                title="S3 Block Public Access settings disabled",
                resource=f"arn:aws:s3:::{name}",
                severity="High" if len(disabled) == 4 else "Medium",
                cis_control="",          # fill from CIS benchmark
                iso_27001="",            # fill from Annex A
                dora_article="Article 9 — Protection and prevention",
                description=(
                    f"{len(disabled)} of 4 Block Public Access controls are "
                    f"disabled ({', '.join(disabled)}). The bucket is not "
                    "currently public, but no guardrail prevents it becoming so."
                ),
                remediation="Enable all four Block Public Access settings.",
            ))
    return findings


# ---------------------------------------------------------------
# CHECK 2 — Security groups open to the internet
# ---------------------------------------------------------------

def check_open_security_groups(session) -> list[Finding]:
    ec2 = session.client("ec2")
    findings = []

    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for rule in sg["IpPermissions"]:
            open_to_world = any(
                r["CidrIp"] == "0.0.0.0/0" for r in rule.get("IpRanges", [])
            )
            if not open_to_world:
                continue

            port = rule.get("FromPort", "all")
            findings.append(Finding(
                finding_id="AWS-EC2-001",
                title=f"Security group allows ingress from 0.0.0.0/0 on port {port}",
                resource=sg["GroupId"],
                severity="Critical" if port in (22, 3389) else "High",
                cis_control="",
                iso_27001="",
                dora_article="Article 9 — Protection and prevention",
                description=(
                    f"Security group '{sg['GroupName']}' permits inbound traffic "
                    f"from any internet address on port {port}."
                ),
                remediation="Restrict the source CIDR to known administrative ranges.",
            ))
    return findings



def check_iam_users(session) -> list[Finding]:
    iam = session.client("iam")
    findings = []

    for user in iam.list_users()["Users"]:
        name = user["UserName"]

        # --- Excessive privilege ---
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]

        if any(p["PolicyName"] == "AdministratorAccess" for p in attached):
            findings.append(Finding(
                finding_id="AWS-IAM-001",
                title="IAM user has full administrative privileges",
                resource=user["Arn"],
                severity="High",
                cis_control="",
                iso_27001="",
                dora_article="Article 9 — Protection and prevention",
                description=(
                    f"User '{name}' has the AWS-managed AdministratorAccess policy "
                    "attached directly, granting unrestricted permissions across all "
                    "services and resources in the account."
                ),
                remediation=(
                    "Replace with a least-privilege policy scoped to the user's "
                    "actual responsibilities."
                ),
            ))

        # --- Missing MFA ---
        mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]

        if not mfa:
            findings.append(Finding(
                finding_id="AWS-IAM-002",
                title="IAM user has no MFA device enabled",
                resource=user["Arn"],
                severity="High",
                cis_control="",
                iso_27001="",
                dora_article="Article 9 — Protection and prevention",
                description=(
                    f"User '{name}' can authenticate using a password alone. "
                    "No second authentication factor is registered."
                ),
                remediation="Enrol a virtual or hardware MFA device for this user.",
            ))

    return findings

def check_unencrypted_volumes(session) -> list[Finding]:
    ec2 = session.client("ec2")
    findings = []

    for volume in ec2.describe_volumes()["Volumes"]:
        if volume["Encrypted"]:
            continue

        findings.append(Finding(
            finding_id="AWS-EBS-001",
            title="EBS volume is not encrypted at rest",
            resource=volume["VolumeId"],
            severity="Medium",
            cis_control="",
            iso_27001="",
            dora_article="Article 9 — Protection and prevention",
            description=(
                f"Volume {volume['VolumeId']} ({volume['Size']} GiB, "
                f"{volume['AvailabilityZone']}) stores data without encryption "
                "at rest. Data would be readable from the underlying storage "
                "or from any snapshot taken of this volume."
            ),
            remediation=(
                "Enable EBS encryption by default for the region, and migrate "
                "existing volumes via encrypted snapshots."
            ),
        ))

    return findings

CHECKS = [
    check_s3_public_access,
    check_open_security_groups,
    check_iam_users,
    check_unencrypted_volumes,
]


def main():
    session = boto3.Session()
    findings = [f for check in CHECKS for f in check(session)]

    print(json.dumps([asdict(f) for f in findings], indent=2))
    print(f"\n{len(findings)} findings across {len(CHECKS)} checks.")


if __name__ == "__main__":
    main()
