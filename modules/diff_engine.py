import json
import hashlib
from datetime import datetime

# ─────────────────────────────────────────
# FINDING FINGERPRINT
# ─────────────────────────────────────────

def fingerprint(finding: dict) -> str:
    """
    Create a stable fingerprint for a finding.
    Used to match same finding across different scans.
    Based on check + url + module — not the full detail
    (detail can change slightly between scans).
    """
    key = "|".join([
        finding.get("check",  "").strip().lower(),
        finding.get("url",    "").strip().lower(),
        finding.get("module", "").strip().lower(),
        finding.get("param",  "").strip().lower(),
    ])
    return hashlib.md5(key.encode()).hexdigest()


# ─────────────────────────────────────────
# DIFF ENGINE
# ─────────────────────────────────────────

def diff_findings(old_findings: list, new_findings: list) -> dict:
    """
    Compare two scan results and categorize findings.

    Returns:
        new:       findings in new scan but NOT in old
        fixed:     findings in old scan but NOT in new
        unchanged: findings in both scans
        worsened:  findings that exist in both but severity increased
    """
    old_fps = {fingerprint(f): f for f in old_findings
               if f.get("severity") != "info"}
    new_fps = {fingerprint(f): f for f in new_findings
               if f.get("severity") != "info"}

    severity_order = {"critical": 4, "high": 3,
                      "medium": 2, "low": 1, "info": 0}

    new_found  = []
    fixed      = []
    unchanged  = []
    worsened   = []

    # Find new and worsened
    for fp, finding in new_fps.items():
        if fp not in old_fps:
            new_found.append(finding)
        else:
            old_sev = severity_order.get(
                old_fps[fp].get("severity", "info"), 0)
            new_sev = severity_order.get(
                finding.get("severity", "info"), 0)
            if new_sev > old_sev:
                worsened.append({
                    **finding,
                    "previous_severity": old_fps[fp].get("severity"),
                })
            else:
                unchanged.append(finding)

    # Find fixed
    for fp, finding in old_fps.items():
        if fp not in new_fps:
            fixed.append(finding)

    return {
        "new":       new_found,
        "fixed":     fixed,
        "unchanged": unchanged,
        "worsened":  worsened,
        "summary": {
            "new":       len(new_found),
            "fixed":     len(fixed),
            "unchanged": len(unchanged),
            "worsened":  len(worsened),
        }
    }


def get_risk_trend(scans: list) -> str:
    """
    Given a list of scan records ordered by date,
    return trend: improving / worsening / stable
    """
    if len(scans) < 2:
        return "stable"

    severity_score = {
        "CRITICAL": 5, "HIGH": 4,
        "MEDIUM": 3,   "LOW": 2, "CLEAN": 0,
    }

    scores = [
        severity_score.get(s.get("risk_level", "CLEAN"), 0)
        for s in scans[-5:]  # last 5 scans
    ]

    if len(scores) < 2:
        return "stable"

    if scores[-1] < scores[0]:
        return "improving"
    elif scores[-1] > scores[0]:
        return "worsening"
    return "stable"


def build_diff_report(old_scan: dict, new_scan: dict) -> dict:
    """
    Build a complete diff report between two scans.
    """
    old_findings = old_scan.get("findings", [])
    new_findings = new_scan.get("findings", [])

    diff = diff_findings(old_findings, new_findings)

    return {
        "generated_at":  datetime.now().isoformat(),
        "target":        new_scan.get("target", ""),
        "old_scan_id":   old_scan.get("id", ""),
        "new_scan_id":   new_scan.get("id", ""),
        "old_scan_date": old_scan.get("created_at", ""),
        "new_scan_date": new_scan.get("created_at", ""),
        "diff":          diff,
        "risk_changed":  (
            old_scan.get("risk_level") != new_scan.get("risk_level")
        ),
        "old_risk":      old_scan.get("risk_level", "CLEAN"),
        "new_risk":      new_scan.get("risk_level", "CLEAN"),
        "needs_attention": (
            len(diff["new"]) > 0 or len(diff["worsened"]) > 0
        ),
    }