"""Data model shared by all checks: one Finding = one result of one check on one resource."""

from dataclasses import dataclass, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Used to sort findings (most severe first) and to decide the exit code.
SEVERITY_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}


class Status(str, Enum):
    PASS = "PASS"    # control is satisfied
    FAIL = "FAIL"    # misconfiguration found
    ERROR = "ERROR"  # check could not run (usually missing permission)


@dataclass
class Finding:
    check_id: str       # our own ID, e.g. "IAM-01"
    cis_id: str         # CIS AWS Foundations Benchmark v5.0.0 requirement, e.g. "1.3"
    title: str
    severity: Severity
    status: Status
    resource: str       # what was checked: account, bucket name, security group ID...
    details: str        # why it passed/failed, in plain English
    remediation: str = ""

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d
