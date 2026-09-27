"""IAM checks — CIS AWS Foundations Benchmark v5.0.0, section 1."""

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from .models import Finding, Severity, Status

KEY_MAX_AGE_DAYS = 90       # CIS 1.13
UNUSED_CRED_DAYS = 45       # CIS 1.11
MIN_PASSWORD_LENGTH = 14    # CIS 1.7


def _days_since(dt):
    return (datetime.now(timezone.utc) - dt).days


def check_root_account(iam):
    """CIS 1.3 (no root access keys) and 1.4 (root MFA).

    get_account_summary returns account-wide counters, including two flags
    about the root user - one API call, no need to parse the credential report.
    """
    summary = iam.get_account_summary()["SummaryMap"]
    findings = []

    has_keys = summary.get("AccountAccessKeysPresent", 0) > 0
    findings.append(Finding(
        "IAM-01", "1.3", "Root user has no access keys", Severity.CRITICAL,
        Status.FAIL if has_keys else Status.PASS, "root",
        "Root user has active access keys - anyone holding them has unrestricted "
        "control over the account." if has_keys else "No root access keys found.",
        "Delete root access keys; use IAM roles for programmatic access.",
    ))

    mfa_on = summary.get("AccountMFAEnabled", 0) == 1
    findings.append(Finding(
        "IAM-02", "1.4", "MFA enabled for root user", Severity.CRITICAL,
        Status.PASS if mfa_on else Status.FAIL, "root",
        "Root MFA is enabled." if mfa_on else "Root user can sign in with a password only.",
        "Enable MFA (preferably hardware) on the root user.",
    ))
    return findings


def check_password_policy(iam):
    """CIS 1.7 (min length 14) and 1.8 (prevent password reuse)."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        policy = {}  # no policy at all = AWS defaults, which fail both checks

    length = policy.get("MinimumPasswordLength", 0)
    reuse = policy.get("PasswordReusePrevention", 0)
    return [
        Finding(
            "IAM-03", "1.7", "Password policy requires 14+ characters", Severity.MEDIUM,
            Status.PASS if length >= MIN_PASSWORD_LENGTH else Status.FAIL, "account",
            f"Minimum password length is {length or 'not set'}.",
            "Set MinimumPasswordLength to 14 or more.",
        ),
        Finding(
            "IAM-04", "1.8", "Password policy prevents reuse", Severity.LOW,
            Status.PASS if reuse >= 24 else Status.FAIL, "account",
            f"Password reuse prevention remembers {reuse} previous passwords.",
            "Set PasswordReusePrevention to 24.",
        ),
    ]


def check_users(iam):
    """Per-user checks: CIS 1.9 (MFA for console users), 1.11 (unused
    credentials), 1.13 (key rotation), 1.14 (no policies attached directly)."""
    findings = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            findings += _check_user_mfa(iam, name)
            findings += _check_user_keys(iam, name)
            findings += _check_user_direct_policies(iam, name)
    return findings


def _check_user_mfa(iam, name):
    try:
        iam.get_login_profile(UserName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return []  # no console password -> MFA requirement does not apply
        raise
    has_mfa = bool(iam.list_mfa_devices(UserName=name)["MFADevices"])
    return [Finding(
        "IAM-05", "1.9", "MFA enabled for console user", Severity.HIGH,
        Status.PASS if has_mfa else Status.FAIL, f"user/{name}",
        "User has MFA." if has_mfa else "User can log in to the console with a password only.",
        "Enforce MFA for every user with a console password.",
    )]


def _check_user_keys(iam, name):
    findings = []
    for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
        if key["Status"] != "Active":
            continue
        key_id = key["AccessKeyId"]
        age = _days_since(key["CreateDate"])
        findings.append(Finding(
            "IAM-06", "1.13", "Access key rotated within 90 days", Severity.MEDIUM,
            Status.PASS if age <= KEY_MAX_AGE_DAYS else Status.FAIL,
            f"user/{name}/key/{key_id}", f"Key is {age} days old.",
            "Rotate the key: create a new one, update the application, delete the old one.",
        ))

        last_used = iam.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"]
        used_at = last_used.get("LastUsedDate")
        idle = _days_since(used_at) if used_at else age  # never used -> idle since creation
        if idle > UNUSED_CRED_DAYS:
            findings.append(Finding(
                "IAM-07", "1.11", "No unused credentials older than 45 days", Severity.MEDIUM,
                Status.FAIL, f"user/{name}/key/{key_id}",
                f"Active key unused for {idle} days - forgotten keys are a common breach entry point.",
                "Deactivate and delete keys that are no longer used.",
            ))
    return findings


def _check_user_direct_policies(iam, name):
    attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
    inline = iam.list_user_policies(UserName=name)["PolicyNames"]
    names = [p["PolicyName"] for p in attached] + inline
    if not names:
        return []
    admin = "AdministratorAccess" in names
    return [Finding(
        "IAM-08", "1.14", "Permissions granted through groups, not directly",
        Severity.HIGH if admin else Severity.LOW, Status.FAIL, f"user/{name}",
        f"Policies attached directly to user: {', '.join(names)}.",
        "Move permissions to IAM groups or roles and detach them from the user.",
    )]


def run(session):
    iam = session.client("iam")
    return check_root_account(iam) + check_password_policy(iam) + check_users(iam)
