#!/usr/bin/env python3
"""
SecurePipe scorecard generator.

Reads the raw JSON output of Gitleaks, Trivy and Semgrep (whichever are
present in the working directory), converts them into one unified
"security score" out of 100, and writes:

  - scorecard.json   machine-readable summary (score, grade, issue list)
  - dashboard.html   a self-contained HTML page for the faculty dashboard

Designed to be forgiving: if a tool's report file is missing, empty, or
malformed, that tool is simply skipped rather than crashing the pipeline.
"""

import json
import os
from datetime import datetime, timezone

TRIVY_FILE = "trivy-report.json"
SEMGREP_FILE = "semgrep-report.json"
GITLEAKS_FILE = "gitleaks-report.json"

# Penalty points per finding, by severity. Tune these for your rubric.
SEVERITY_WEIGHTS = {
    "CRITICAL": 12,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "SECRET": 15,   # any hardcoded secret is treated as very severe
}


def safe_load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            content = f.read().strip()
            if not content:
                return None
            return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return None


def parse_gitleaks(data):
    """Gitleaks JSON report is a flat list of leak findings."""
    issues = []
    if not data:
        return issues
    findings = data if isinstance(data, list) else data.get("findings", [])
    for leak in findings:
        issues.append({
            "tool": "Gitleaks",
            "severity": "SECRET",
            "title": leak.get("RuleID", "Hardcoded secret detected"),
            "location": f"{leak.get('File', 'unknown')}:{leak.get('StartLine', '?')}",
        })
    return issues


def parse_trivy(data):
    """Trivy JSON report groups vulnerabilities under Results[].Vulnerabilities[]."""
    issues = []
    if not data:
        return issues
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = (vuln.get("Severity") or "LOW").upper()
            issues.append({
                "tool": "Trivy",
                "severity": sev if sev in SEVERITY_WEIGHTS else "LOW",
                "title": f"{vuln.get('VulnerabilityID', 'CVE')} in {vuln.get('PkgName', 'dependency')}",
                "location": result.get("Target", "unknown"),
            })
    return issues


def parse_semgrep(data):
    """Semgrep JSON report lists findings under results[], severity as ERROR/WARNING/INFO."""
    issues = []
    if not data:
        return issues
    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    for finding in data.get("results", []) or []:
        raw_sev = (finding.get("extra", {}).get("severity") or "WARNING").upper()
        sev = sev_map.get(raw_sev, "LOW")
        issues.append({
            "tool": "Semgrep",
            "severity": sev,
            "title": finding.get("check_id", "Static analysis finding"),
            "location": f"{finding.get('path', 'unknown')}:{finding.get('start', {}).get('line', '?')}",
        })
    return issues


def compute_score(issues):
    penalty = sum(SEVERITY_WEIGHTS.get(i["severity"], 1) for i in issues)
    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "F"
    return score, grade


def grade_color(grade):
    return {"A": "#0f6e56", "B": "#854f0b", "C": "#993c1d", "F": "#791f1f"}.get(grade, "#5f5e5a")


def build_dashboard_html(score, grade, issues, generated_at):
    color = grade_color(grade)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECRET": 0}
    for i in issues:
        counts[i["severity"]] = counts.get(i["severity"], 0) + 1

    rows = "\n".join(
        f"<tr><td>{i['tool']}</td><td class='sev sev-{i['severity'].lower()}'>{i['severity']}</td>"
        f"<td>{i['title']}</td><td>{i['location']}</td></tr>"
        for i in issues
    ) or "<tr><td colspan='4' class='clean'>No issues found. Clean scan.</td></tr>"

    summary_cards = "".join(
        f"<div class='card'><div class='count'>{counts[sev]}</div><div class='label'>{sev.title()}</div></div>"
        for sev in ["SECRET", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecurePipe Security Scorecard</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#f5f4f0; color:#2c2c2a; margin:0; padding:32px; }}
  .wrap {{ max-width: 880px; margin: 0 auto; }}
  h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 4px; }}
  .meta {{ color:#5f5e5a; font-size: 13px; margin-bottom: 24px; }}
  .score-banner {{ display:flex; align-items:center; gap:24px; background:#fff; border-radius:12px; padding:24px; border:1px solid #e0ded5; margin-bottom:24px; }}
  .score-circle {{ width:96px; height:96px; border-radius:50%; display:flex; align-items:center; justify-content:center;
                    font-size:32px; font-weight:600; color:#fff; background:{color}; flex-shrink:0; }}
  .score-detail h2 {{ margin:0 0 4px; font-size:18px; }}
  .score-detail p {{ margin:0; color:#5f5e5a; font-size:14px; }}
  .cards {{ display:flex; gap:12px; margin-bottom:24px; }}
  .card {{ flex:1; background:#fff; border:1px solid #e0ded5; border-radius:10px; padding:16px; text-align:center; }}
  .card .count {{ font-size:24px; font-weight:600; }}
  .card .label {{ font-size:12px; color:#5f5e5a; margin-top:4px; }}
  table {{ width:100%; border-collapse: collapse; background:#fff; border-radius:10px; overflow:hidden; border:1px solid #e0ded5; }}
  th, td {{ text-align:left; padding:10px 14px; font-size:13px; border-bottom:1px solid #eeece5; }}
  th {{ background:#f1efe8; font-weight:600; }}
  .sev {{ font-weight:600; }}
  .sev-critical, .sev-secret {{ color:#791f1f; }}
  .sev-high {{ color:#993c1d; }}
  .sev-medium {{ color:#854f0b; }}
  .sev-low {{ color:#5f5e5a; }}
  .clean {{ text-align:center; color:#0f6e56; font-weight:600; padding:20px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>SecurePipe security scorecard</h1>
  <div class="meta">Generated {generated_at} &middot; Gitleaks + Trivy + Semgrep</div>

  <div class="score-banner">
    <div class="score-circle">{score}</div>
    <div class="score-detail">
      <h2>Grade {grade}</h2>
      <p>{len(issues)} total finding(s) across secret, dependency and static-analysis scans.</p>
    </div>
  </div>

  <div class="cards">
    {summary_cards}
  </div>

  <table>
    <thead><tr><th>Tool</th><th>Severity</th><th>Finding</th><th>Location</th></tr></thead>
    <tbody>
    {rows}
    </tbody>
  </table>
</div>
</body>
</html>
"""


def main():
    gitleaks_data = safe_load_json(GITLEAKS_FILE)
    trivy_data = safe_load_json(TRIVY_FILE)
    semgrep_data = safe_load_json(SEMGREP_FILE)

    issues = []
    issues += parse_gitleaks(gitleaks_data)
    issues += parse_trivy(trivy_data)
    issues += parse_semgrep(semgrep_data)

    score, grade = compute_score(issues)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    scorecard = {
        "generated_at": generated_at,
        "score": score,
        "grade": grade,
        "issue_count": len(issues),
        "issues": issues,
    }

    with open("scorecard.json", "w") as f:
        json.dump(scorecard, f, indent=2)

    with open("dashboard.html", "w") as f:
        f.write(build_dashboard_html(score, grade, issues, generated_at))

    print(f"SecurePipe scorecard: {score}/100 (grade {grade}), {len(issues)} issue(s). "
          f"See scorecard.json and dashboard.html")


if __name__ == "__main__":
    main()
