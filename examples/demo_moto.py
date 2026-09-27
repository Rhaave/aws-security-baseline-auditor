"""Run the auditor against a fake, deliberately misconfigured AWS account (moto).

Lets anyone see the tool working without an AWS account:
    pip install -r requirements-dev.txt
    python3 examples/demo_moto.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from moto import mock_aws

os.environ.update(AWS_ACCESS_KEY_ID="demo", AWS_SECRET_ACCESS_KEY="demo", AWS_DEFAULT_REGION="eu-central-1")

with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
    import boto3
    import audit

    region = "eu-central-1"
    iam = boto3.client("iam")
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    # Weak password policy, console user without MFA, admin policy attached directly.
    iam.update_account_password_policy(MinimumPasswordLength=8)
    iam.create_user(UserName="marketing-intern")
    iam.create_login_profile(UserName="marketing-intern", Password="Summer2026!")
    iam.create_user(UserName="legacy-admin")
    iam.attach_user_policy(UserName="legacy-admin", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_access_key(UserName="legacy-admin")

    # One public bucket, one properly locked down.
    for b in ("customer-exports", "app-backups"):
        s3.create_bucket(Bucket=b, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_policy(Bucket="customer-exports", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::customer-exports/*"}]}))
    s3.put_public_access_block(Bucket="app-backups", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

    # SSH open to the internet.
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="bastion", Description="bastion", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    # No CloudTrail at all.

    sys.argv = ["audit.py", "--regions", region, "--html", "examples/sample_report.html"]
    audit.main()
