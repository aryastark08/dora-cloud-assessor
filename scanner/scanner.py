"""
DORA Cloud Compliance Assessor: AWS scanner.

Each check detects one kind of misconfiguration and reports only the facts:
which finding, which resource, what exactly is wrong. The meaning of each
finding (regulation, controls, risk score, owner) is added afterwards from
mappings.py, so detection and interpretation stay separate.

Usage:
    python3 scanner.py                     # writes findings.json, account IDs redacted
    python3 scanner.py --no-redact         # keep real account IDs (do not publish)
    python3 scanner.py --region eu-north-1
"""

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import boto3

from mappings import CONTROLS, DORA_ARTICLES, rating_for

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_PORTS = (22, 3389)  # SSH, RDP


@dataclass
class Finding:
    finding_id: str
    resource: str
    detail: str
    region: str
    # Filled in from mappings.py
    title: str = ""
    risk_statement: str = ""
    dora_article: str = ""
    dora_title: str = ""
    iso_27001: list = field(default_factory=list)
    cis_title: str = ""
    cis_id: str = ""
    likelihood: int = 0
    impact: int = 0
    risk_score: int = 0
    severity: str = ""
    effort: str = ""
    owner: str = ""
    remediation: str = ""


def raw(finding_id, resource, detail, region, impact=None):
    """What a check returns: the facts, plus an optional impact override."""
    return {"finding_id": finding_id, "resource": resource, "detail": detail,
            "region": region, "impact": impact}


def enrich(item) -> Finding:
    """Attach regulatory mapping and risk score to a raw finding."""
    m = CONTROLS[item["finding_id"]]
    impact = item["impact"] or m["impact"]
    score = m["likelihood"] * impact
    return Finding(
        finding_id=item["finding_id"],
        resource=item["resource"],
        detail=item["detail"],
        region=item["region"],
        title=m["title"],
        risk_statement=m["risk_statement"],
        dora_article=m["dora"],
        dora_title=DORA_ARTICLES[m["dora"]],
        iso_27001=m["iso"],
        cis_title=m["cis_title"],
        cis_id=m["cis_id"],
        likelihood=m["likelihood"],
        impact=impact,
        risk_score=score,
        severity=rating_for(score),
        effort=m["effort"],
        owner=m["owner"],
        remediation=m["remediation"],
    )


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

def check_s3(session, region):
    s3 = session.client("s3")
    out = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"

        # Block Public Access
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except s3.exceptions.ClientError:
            cfg = {k: False for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                      "BlockPublicPolicy", "RestrictPublicBuckets")}
        disabled = [k for k, v in cfg.items() if not v]
        if disabled:
            out.append(raw(
                "AWS-S3-001", arn,
                f"{len(disabled)} of 4 Block Public Access settings are disabled "
                f"({', '.join(disabled)}). The bucket is not necessarily public today, "
                "but no guardrail prevents it from becoming public.",
                region
            ))

        # Versioning
        status = s3.get_bucket_versioning(Bucket=name).get("Status", "Never enabled")
        if status != "Enabled":
            out.append(raw(
                "AWS-S3-002", arn,
                f"Versioning status is '{status}'. Overwritten or deleted objects "
                "cannot be recovered from the bucket itself.",
                region,
            ))
    return out


# ---------------------------------------------------------------------------
# EC2: security groups and volumes
# ---------------------------------------------------------------------------

def _rule_exposes_admin_port(rule):
    if rule.get("IpProtocol") == "-1":           # all traffic, all ports
        return True
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None or high is None:
        return False
    return any(low <= port <= high for port in ADMIN_PORTS)


def _rule_open_to_world(rule):
    v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
    return v4 or v6


def check_security_groups(session, region):
    ec2 = session.client("ec2", region_name=region)
    out = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for rule in sg["IpPermissions"]:
            if _rule_open_to_world(rule) and _rule_exposes_admin_port(rule):
                if rule.get("IpProtocol") == "-1":
                    ports = "all ports"
                elif rule["FromPort"] == rule["ToPort"]:
                    ports = f"port {rule['FromPort']}"
                else:
                    ports = f"ports {rule['FromPort']}-{rule['ToPort']}"
                out.append(raw(
                    "AWS-EC2-001", sg["GroupId"],
                    f"Security group '{sg['GroupName']}' permits inbound traffic from any "
                    f"internet address on {ports}, which includes remote administration.",
                    region,
                ))
    return out


def check_volumes(session, region):
    ec2 = session.client("ec2", region_name=region)
    out = []
    for vol in ec2.describe_volumes()["Volumes"]:
        if vol["Encrypted"]:
            continue
        out.append(raw(
            "AWS-EBS-001", vol["VolumeId"],
            f"Volume {vol['VolumeId']} ({vol['Size']} GiB, {vol['AvailabilityZone']}) "
            "stores data unencrypted. Data is readable from any snapshot of this volume.",
            region,
        ))
    return out


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

def check_iam_users(session, region):
    iam = session.client("iam")
    out = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name, arn = user["UserName"], user["Arn"]

            attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
            is_admin = any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in attached)

            try:
                iam.get_login_profile(UserName=name)
                has_console = True
            except iam.exceptions.NoSuchEntityException:
                has_console = False

            has_mfa = bool(iam.list_mfa_devices(UserName=name)["MFADevices"])

            if is_admin:
                out.append(raw(
                    "AWS-IAM-001", arn,
                    f"User '{name}' has the AWS-managed AdministratorAccess policy attached "
                    "directly, granting unrestricted access to every service and resource.",
                    "global",
                ))

            # CIS scopes the MFA control to users who can sign in to the console.
            if has_console and not has_mfa:
                out.append(raw(
                    "AWS-IAM-002", arn,
                    f"User '{name}' can sign in to the console with a password alone."
                    + (" The user is also a full administrator, so a stolen password "
                       "would compromise the entire account." if is_admin else ""),
                    "global",
                    impact=5 if is_admin else None,
                ))
    return out


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

def check_cloudtrail(session, region):
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=True)["trailList"]

    for trail in trails:
        home = session.client("cloudtrail", region_name=trail["HomeRegion"])
        if home.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
            return []

    return [raw(
        "AWS-CT-001", f"cloudtrail:{region}",
        f"No CloudTrail trail is actively logging API activity in {region}. "
        "There is no durable record of who changed what in the account.",
        region,
    )]


CHECKS = [
    check_s3,
    check_security_groups,
    check_volumes,
    check_iam_users,
    check_cloudtrail,
]


# ---------------------------------------------------------------------------

ACCOUNT_ID = re.compile(r"(?<!\d)\d{12}(?!\d)")


def redact(text: str) -> str:
    return ACCOUNT_ID.sub("<account-id>", text)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--region", help="AWS region (default: your CLI configuration)")
    parser.add_argument("--out", default="findings.json")
    parser.add_argument("--no-redact", action="store_true",
                        help="keep real account IDs in the output")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    region = session.region_name
    if not region:
        raise SystemExit("No region set. Use --region or run 'aws configure'.")

    account = session.client("sts").get_caller_identity()["Account"]

    findings = [enrich(item) for check in CHECKS for item in check(session, region)]
    findings.sort(key=lambda f: -f.risk_score)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "region": region,
        "account": account,
        "checks_run": [c.__name__ for c in CHECKS],
        "findings": [asdict(f) for f in findings],
    }

    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if not args.no_redact:
        text = redact(text)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)

    print(f"{'Score':>5}  {'Severity':<9} {'ID':<12} Resource")
    for f in findings:
        resource = f.resource if args.no_redact else redact(f.resource)
        print(f"{f.risk_score:>5}  {f.severity:<9} {f.finding_id:<12} {resource}")
    print(f"\n{len(findings)} findings from {len(CHECKS)} checks -> {args.out}")


if __name__ == "__main__":
    main()
