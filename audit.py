#!/usr/bin/env python3
"""
AWS Security Baseline Auditor
Read-only scanner for common AWS misconfigurations, mapped to
CIS AWS Foundations Benchmark v5.0.0.

Usage:
  python3 audit.py                          # default profile and region
  python3 audit.py --profile audit --regions eu-central-1 us-east-1
  python3 audit.py --html report.html --json report.json --csv report.csv
  python3 audit.py --fail-on HIGH           # exit code 1 if any HIGH/CRITICAL fails (for CI)
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from auditor import cloudtrail, ec2, iam, report, s3
from auditor.models import SEVERITY_RANK, Finding, Severity, Status


def safe_run(name, func, *args):
    """Run one group of checks. If the credentials lack permission, report an
    ERROR finding instead of crashing - a partial audit is better than none."""
    try:
        return func(*args)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return [Finding(f"{name}-ERR", "-", f"{name} checks could not run", Severity.LOW,
                        Status.ERROR, name, f"{code}: {e.response['Error'].get('Message', '')}",
                        "Grant the SecurityAudit managed policy to the identity running the audit.")]


def main():
    parser = argparse.ArgumentParser(description="Read-only AWS security baseline audit (CIS v5.0.0).")
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--regions", nargs="+", help="Regions for EC2 checks (default: session region)")
    parser.add_argument("--json", help="Write JSON report to this path")
    parser.add_argument("--csv", help="Write CSV report to this path")
    parser.add_argument("--html", help="Write HTML report to this path")
    parser.add_argument("--fail-on", choices=[s.value for s in Severity],
                        help="Exit with code 1 if a FAIL of this severity or higher is found")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
    except NoCredentialsError:
        sys.exit("No AWS credentials found. Configure a profile with read-only (SecurityAudit) access.")

    regions = args.regions or [session.region_name or "eu-central-1"]

    findings = []
    findings += safe_run("IAM", iam.run, session)
    findings += safe_run("S3", s3.run, session, account_id)
    findings += safe_run("CLOUDTRAIL", cloudtrail.run, session)
    findings += safe_run("EC2", ec2.run, session, regions)

    report.print_console(findings, account_id)
    if args.json:
        report.write_json(findings, account_id, args.json)
    if args.csv:
        report.write_csv(findings, args.csv)
    if args.html:
        report.write_html(findings, account_id, args.html)

    if args.fail_on:
        threshold = SEVERITY_RANK[Severity(args.fail_on)]
        if any(f.status == Status.FAIL and SEVERITY_RANK[f.severity] >= threshold for f in findings):
            sys.exit(1)


if __name__ == "__main__":
    main()
