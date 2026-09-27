"""S3 checks — CIS AWS Foundations Benchmark v5.0.0, section 2.1."""

import json

from botocore.exceptions import ClientError

from .models import Finding, Severity, Status

BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _all_flags_on(config):
    return all(config.get(flag, False) for flag in BPA_FLAGS)


def check_account_public_access_block(s3control, account_id):
    """CIS 2.1.4 at account level: one switch that protects every bucket."""
    try:
        config = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        config = {}
    ok = _all_flags_on(config)
    return [Finding(
        "S3-01", "2.1.4", "Account-level S3 Block Public Access enabled", Severity.HIGH,
        Status.PASS if ok else Status.FAIL, f"account/{account_id}",
        "All four Block Public Access settings are on." if ok
        else "Account-level Block Public Access is off or incomplete - every bucket relies on its own settings.",
        "Enable all four Block Public Access settings at account level.",
    )]


def check_buckets(s3):
    findings = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        policy = _get_policy(s3, name)
        findings += _check_bucket_public(s3, name, policy)
        findings += _check_bucket_tls(name, policy)
    return findings


def _get_policy(s3, name):
    """Return the bucket policy as a list of statements ([] if there is none)."""
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
        return []
    statements = policy.get("Statement", [])
    return [statements] if isinstance(statements, dict) else statements


def _statement_is_public(st):
    """Allow + Principal "*" (or {"AWS": "*"}) + no Condition = open to anyone."""
    if st.get("Effect") != "Allow" or st.get("Condition"):
        return False
    principal = st.get("Principal")
    if isinstance(principal, dict):
        principal = principal.get("AWS")
    if isinstance(principal, list):
        return "*" in principal
    return principal == "*"


def _check_bucket_public(s3, name, statements):
    """CIS 2.1.4 at bucket level + the real question: is the bucket public RIGHT NOW?

    Two independent signals: AWS's own evaluation (GetBucketPolicyStatus)
    and our reading of the policy. Either one is enough to flag the bucket.
    """
    try:
        config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        config = {}

    aws_says_public = False
    if statements:
        try:
            aws_says_public = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"].get("IsPublic", False)
        except ClientError:
            pass  # fall back to our own policy analysis below

    # Block Public Access (RestrictPublicBuckets) neutralises a public policy.
    blocked = config.get("RestrictPublicBuckets", False)
    is_public = not blocked and (aws_says_public or any(_statement_is_public(st) for st in statements))

    if is_public:
        # A public bucket is the classic cloud data leak - highest priority.
        return [Finding(
            "S3-02", "2.1.4", "Bucket is not publicly accessible", Severity.CRITICAL,
            Status.FAIL, f"s3://{name}",
            "Bucket policy grants public access - anyone on the internet can reach its objects.",
            "Remove the public statement from the bucket policy and enable Block Public Access.",
        )]
    ok = _all_flags_on(config)
    return [Finding(
        "S3-02", "2.1.4", "Bucket is not publicly accessible", Severity.MEDIUM,
        Status.PASS if ok else Status.FAIL, f"s3://{name}",
        "Not public, Block Public Access fully enabled." if ok
        else "Not public now, but Block Public Access is not fully enabled - one policy change away from a leak.",
        "Enable all four Block Public Access settings on the bucket.",
    )]


def _check_bucket_tls(name, statements):
    """CIS 2.1.1: bucket policy must deny requests sent over plain HTTP.

    We look for a Deny statement conditioned on aws:SecureTransport = false.
    """
    enforced = any(
        st.get("Effect") == "Deny"
        and str(st.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport", "")).lower() == "false"
        for st in statements
    )
    return [Finding(
        "S3-03", "2.1.1", "Bucket denies non-HTTPS requests", Severity.LOW,
        Status.PASS if enforced else Status.FAIL, f"s3://{name}",
        "Policy denies requests without TLS." if enforced
        else "No policy statement denies HTTP (unencrypted) requests.",
        'Add a Deny statement with Condition {"Bool": {"aws:SecureTransport": "false"}}.',
    )]


def run(session, account_id):
    return (check_account_public_access_block(session.client("s3control"), account_id)
            + check_buckets(session.client("s3")))
