"""Tests run against moto - an in-memory fake of AWS. No real account, no cost.

Each test builds a small, deliberately misconfigured (or clean) environment
and checks that the auditor reports exactly what we expect.
"""

import json

import boto3
import pytest
from moto import mock_aws

from auditor import cloudtrail, ec2, iam, s3
from auditor.models import Status

REGION = "eu-central-1"


@pytest.fixture
def session(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    # load_aws_managed_policies: make AWS-managed policies like AdministratorAccess exist in the fake account
    with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
        yield boto3.Session(region_name=REGION)


def by_id(findings, check_id):
    return [f for f in findings if f.check_id == check_id]


# ---------------- IAM ----------------

def test_missing_password_policy_fails(session):
    findings = iam.check_password_policy(session.client("iam"))
    assert all(f.status == Status.FAIL for f in findings)


def test_strong_password_policy_passes(session):
    client = session.client("iam")
    client.update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)
    findings = iam.check_password_policy(client)
    assert all(f.status == Status.PASS for f in findings)


def test_console_user_without_mfa_fails(session):
    client = session.client("iam")
    client.create_user(UserName="alice")
    client.create_login_profile(UserName="alice", Password="Sup3r-Secret-Pass!")
    f = by_id(iam.check_users(client), "IAM-05")
    assert len(f) == 1 and f[0].status == Status.FAIL


def test_user_without_console_access_skips_mfa_check(session):
    client = session.client("iam")
    client.create_user(UserName="ci-bot")  # programmatic only
    assert by_id(iam.check_users(client), "IAM-05") == []


def test_admin_policy_attached_directly_is_high(session):
    client = session.client("iam")
    client.create_user(UserName="bob")
    client.attach_user_policy(UserName="bob", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    f = by_id(iam.check_users(client), "IAM-08")
    assert f[0].status == Status.FAIL and f[0].severity.value == "HIGH"


def test_new_active_key_passes_rotation(session):
    client = session.client("iam")
    client.create_user(UserName="dev")
    client.create_access_key(UserName="dev")
    f = by_id(iam.check_users(client), "IAM-06")
    assert f[0].status == Status.PASS


# ---------------- S3 ----------------

PUBLIC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                   "Resource": "arn:aws:s3:::leaky-bucket/*"}],
}

TLS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
                   "Resource": ["arn:aws:s3:::safe-bucket", "arn:aws:s3:::safe-bucket/*"],
                   "Condition": {"Bool": {"aws:SecureTransport": "false"}}}],
}


def _make_bucket(client, name):
    client.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})


def test_public_bucket_is_critical(session):
    client = session.client("s3")
    _make_bucket(client, "leaky-bucket")
    client.put_bucket_policy(Bucket="leaky-bucket", Policy=json.dumps(PUBLIC_POLICY))
    f = by_id(s3.check_buckets(client), "S3-02")
    assert f[0].status == Status.FAIL and f[0].severity.value == "CRITICAL"


def test_bucket_with_tls_policy_and_bpa_passes(session):
    client = session.client("s3")
    _make_bucket(client, "safe-bucket")
    client.put_bucket_policy(Bucket="safe-bucket", Policy=json.dumps(TLS_POLICY))
    client.put_public_access_block(Bucket="safe-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    findings = s3.check_buckets(client)
    assert by_id(findings, "S3-02")[0].status == Status.PASS
    assert by_id(findings, "S3-03")[0].status == Status.PASS


def test_account_bpa_missing_fails(session):
    account = session.client("sts").get_caller_identity()["Account"]
    f = s3.check_account_public_access_block(session.client("s3control"), account)
    assert f[0].status == Status.FAIL


# ---------------- CloudTrail ----------------

def test_no_trail_fails(session):
    f = by_id(cloudtrail.run(session), "CT-01")
    assert f[0].status == Status.FAIL


def test_logging_multiregion_trail_with_validation_passes(session):
    _make_bucket(session.client("s3"), "trail-logs")
    ct = session.client("cloudtrail")
    ct.create_trail(Name="org-trail", S3BucketName="trail-logs",
                    IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.start_logging(Name="org-trail")
    findings = cloudtrail.run(session)
    assert by_id(findings, "CT-01")[0].status == Status.PASS
    assert by_id(findings, "CT-02")[0].status == Status.PASS


def test_trail_created_but_not_logging_fails(session):
    _make_bucket(session.client("s3"), "trail-logs")
    session.client("cloudtrail").create_trail(Name="idle", S3BucketName="trail-logs", IsMultiRegionTrail=True)
    assert by_id(cloudtrail.run(session), "CT-01")[0].status == Status.FAIL


# ---------------- EC2 ----------------

def test_ssh_open_to_world_fails(session):
    client = session.client("ec2")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = client.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    client.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    f = [x for x in by_id(ec2.check_security_groups(client, REGION), "EC2-01") if sg in x.resource]
    assert f and "SSH/22" in f[0].details


def test_https_open_to_world_is_fine(session):
    client = session.client("ec2")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = client.create_security_group(GroupName="https", Description="https", VpcId=vpc)["GroupId"]
    client.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert not [x for x in by_id(ec2.check_security_groups(client, REGION), "EC2-01") if sg in x.resource]


def test_all_traffic_rule_exposes_rdp_over_ipv6(session):
    client = session.client("ec2")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = client.create_security_group(GroupName="bad", Description="bad", VpcId=vpc)["GroupId"]
    client.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    f = [x for x in by_id(ec2.check_security_groups(client, REGION), "EC2-01") if sg in x.resource]
    assert "RDP/3389 from ::/0" in f[0].details


def test_ebs_default_encryption(session):
    client = session.client("ec2")
    assert ec2.check_ebs_default_encryption(client, REGION)[0].status == Status.FAIL
    client.enable_ebs_encryption_by_default()
    assert ec2.check_ebs_default_encryption(client, REGION)[0].status == Status.PASS


def test_block_public_access_neutralises_public_policy(session):
    client = session.client("s3")
    _make_bucket(client, "leaky-bucket")
    client.put_bucket_policy(Bucket="leaky-bucket", Policy=json.dumps(PUBLIC_POLICY))
    client.put_public_access_block(Bucket="leaky-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    assert by_id(s3.check_buckets(client), "S3-02")[0].status == Status.PASS


def test_full_cli_run_writes_reports(session, tmp_path, monkeypatch):
    """End-to-end: run audit.py's main() against the fake account."""
    import sys
    import audit
    monkeypatch.setattr(sys, "argv", ["audit.py", "--regions", REGION,
                                      "--json", str(tmp_path / "r.json"),
                                      "--html", str(tmp_path / "r.html"),
                                      "--csv", str(tmp_path / "r.csv")])
    audit.main()
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["summary"]["total_checks"] > 0
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")
