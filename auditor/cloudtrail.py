"""CloudTrail checks — CIS AWS Foundations Benchmark v5.0.0, section 3.

CloudTrail is the audit log of every API call in the account. Without it a SOC
has nothing to investigate after an incident.
"""

from .models import Finding, Severity, Status


def run(session):
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

    # CIS 3.1: at least one trail that is multi-region AND actually logging.
    good_trails = [
        t for t in trails
        if t.get("IsMultiRegionTrail") and ct.get_trail_status(Name=t["TrailARN"])["IsLogging"]
    ]
    findings = [Finding(
        "CT-01", "3.1", "Multi-region CloudTrail enabled and logging", Severity.CRITICAL,
        Status.PASS if good_trails else Status.FAIL, "account",
        f"Active multi-region trail(s): {', '.join(t['Name'] for t in good_trails)}." if good_trails
        else "No active multi-region trail - API activity in some or all regions is not recorded.",
        "Create a multi-region trail and make sure logging is started.",
    )]

    # CIS 3.2: log file validation lets you prove logs were not altered.
    for t in trails:
        valid = t.get("LogFileValidationEnabled", False)
        findings.append(Finding(
            "CT-02", "3.2", "CloudTrail log file validation enabled", Severity.MEDIUM,
            Status.PASS if valid else Status.FAIL, f"trail/{t['Name']}",
            "Log file integrity validation is on." if valid
            else "Validation is off - an attacker could edit or delete log files without detection.",
            "Enable log file validation on the trail.",
        ))
    return findings
