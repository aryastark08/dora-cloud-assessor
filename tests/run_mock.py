"""Recreate the Terraform lab in a mocked AWS account and run the scanner."""
import os
import sys

os.environ.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test",
                  AWS_DEFAULT_REGION="eu-north-1",
                  MOTO_IAM_LOAD_MANAGED_POLICIES="true")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import boto3
from moto import mock_aws

REGION = "eu-north-1"

with mock_aws():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="meridian-public-eb962c69",
                     CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_public_access_block(Bucket="meridian-public-eb962c69",
        PublicAccessBlockConfiguration={k: False for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})

    iam = boto3.client("iam")
    for user, console in (("meridian-ops-user", False), ("aishwarya-admin", True)):
        iam.create_user(UserName=user)
        iam.attach_user_policy(UserName=user,
                               PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        if console:
            iam.create_login_profile(UserName=user, Password="Placeholder-123!")

    ec2 = boto3.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="meridian-sg-open", Description="lab")
    ec2.authorize_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1, Encrypted=False)

    import scanner
    sys.argv = ["scanner.py", "--out", os.path.join(os.path.dirname(__file__), "findings.json")]
    scanner.main()
