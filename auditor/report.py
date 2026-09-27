"""Output formats: console summary, JSON, CSV and a standalone HTML report."""

import csv
import html
import json
from collections import Counter
from datetime import datetime, timezone

from .models import SEVERITY_RANK, Status

COLORS = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb"}


def sort_findings(findings):
    """FAIL first, then by severity - the order an analyst should read them in."""
    status_order = {Status.FAIL: 0, Status.ERROR: 1, Status.PASS: 2}
    return sorted(findings, key=lambda f: (status_order[f.status], -SEVERITY_RANK[f.severity], f.check_id))


def summary(findings):
    fails = [f for f in findings if f.status == Status.FAIL]
    return {
        "total_checks": len(findings),
        "passed": sum(f.status == Status.PASS for f in findings),
        "failed": len(fails),
        "errors": sum(f.status == Status.ERROR for f in findings),
        "failed_by_severity": dict(Counter(f.severity.value for f in fails)),
    }


def print_console(findings, account_id):
    s = summary(findings)
    print(f"\nAWS Security Baseline Audit - account {account_id}")
    print(f"Checks: {s['total_checks']}  PASS: {s['passed']}  FAIL: {s['failed']}  ERROR: {s['errors']}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s["failed_by_severity"].get(sev):
            print(f"  {sev}: {s['failed_by_severity'][sev]}")
    print("-" * 78)
    for f in sort_findings(findings):
        if f.status == Status.PASS:
            continue
        print(f"[{f.status.value}] [{f.severity.value:8}] {f.check_id} (CIS {f.cis_id}) {f.title}")
        print(f"    Resource: {f.resource}")
        print(f"    {f.details}")
        if f.remediation and f.status == Status.FAIL:
            print(f"    Fix: {f.remediation}")
    print()


def write_json(findings, account_id, path):
    data = {
        "account_id": account_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark": "CIS AWS Foundations Benchmark v5.0.0",
        "summary": summary(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_csv(findings, path):
    fields = ["status", "severity", "check_id", "cis_id", "title", "resource", "details", "remediation"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for f in sort_findings(findings):
            writer.writerow(f.to_dict())


def write_html(findings, account_id, path):
    s = summary(findings)
    rows = []
    for f in sort_findings(findings):
        color = COLORS[f.severity.value] if f.status == Status.FAIL else "#6b7280"
        rows.append(
            f"<tr><td><b>{f.status.value}</b></td>"
            f"<td><span style='background:{color};color:#fff;padding:2px 8px;border-radius:4px'>{f.severity.value}</span></td>"
            f"<td>{html.escape(f.check_id)}</td><td>{html.escape(f.cis_id)}</td>"
            f"<td>{html.escape(f.title)}</td><td><code>{html.escape(f.resource)}</code></td>"
            f"<td>{html.escape(f.details)}</td><td>{html.escape(f.remediation if f.status == Status.FAIL else '')}</td></tr>"
        )
    sev = " | ".join(f"{k}: {v}" for k, v in s["failed_by_severity"].items()) or "none"
    page = f"""<!doctype html><html><head><meta charset="utf-8">
<title>AWS Security Baseline Audit - {html.escape(account_id)}</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}table{{border-collapse:collapse;width:100%;font-size:14px}}
td,th{{border:1px solid #ddd;padding:6px;vertical-align:top;text-align:left}}th{{background:#f3f4f6}}</style></head><body>
<h1>AWS Security Baseline Audit</h1>
<p>Account <b>{html.escape(account_id)}</b> &middot; CIS AWS Foundations Benchmark v5.0.0 &middot;
generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC</p>
<p><b>{s['total_checks']}</b> checks &middot; <b>{s['passed']}</b> passed &middot; <b>{s['failed']}</b> failed
&middot; <b>{s['errors']}</b> errors &middot; failed by severity: {sev}</p>
<table><tr><th>Status</th><th>Severity</th><th>Check</th><th>CIS</th><th>Title</th><th>Resource</th><th>Details</th><th>Remediation</th></tr>
{''.join(rows)}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
