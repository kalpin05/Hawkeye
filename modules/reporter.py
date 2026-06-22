import json
import os
from datetime import datetime

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

SEVERITY_COLORS = {
    "critical": "#FF4444",
    "high":     "#FF8800",
    "medium":   "#FFCC00",
    "low":      "#00CCFF",
    "info":     "#888888",
}

SEVERITY_BG = {
    "critical": "#3D0000",
    "high":     "#2D1500",
    "medium":   "#2D2500",
    "low":      "#001D2D",
    "info":     "#1A1A1A",
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def get_output_path(filename: str) -> str:
    ensure_reports_dir()
    return os.path.join(REPORTS_DIR, filename)


def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_filename_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def get_risk_level(counts: dict) -> str:
    if counts["critical"] > 0: return "CRITICAL"
    if counts["high"]     > 0: return "HIGH"
    if counts["medium"]   > 0: return "MEDIUM"
    if counts["low"]      > 0: return "LOW"
    return "CLEAN"


# ─────────────────────────────────────────
# JSON REPORT
# ─────────────────────────────────────────

def generate_json(findings: list, target: str = "",
                  output_path: str = "") -> str:
    """Generate JSON report. Returns path to saved file."""
    if not output_path:
        output_path = get_output_path(
            f"hawkeye_report_{get_filename_timestamp()}.json"
        )

    counts     = count_by_severity(findings)
    risk_level = get_risk_level(counts)

    report = {
        "hawkeye_version": "1.0.0",
        "generated_at":    get_timestamp(),
        "target":          target,
        "risk_level":      risk_level,
        "summary": {
            "total":    len(findings),
            "critical": counts["critical"],
            "high":     counts["high"],
            "medium":   counts["medium"],
            "low":      counts["low"],
            "info":     counts["info"],
        },
        "findings": findings,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return output_path


# ─────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────

def generate_html(findings: list, target: str = "",
                  output_path: str = "") -> str:
    """Generate a professional HTML report. Returns path to saved file."""
    if not output_path:
        output_path = get_output_path(
            f"hawkeye_report_{get_filename_timestamp()}.html"
        )

    counts     = count_by_severity(findings)
    risk_level = get_risk_level(counts)
    timestamp  = get_timestamp()

    risk_color = SEVERITY_COLORS.get(risk_level.lower(), "#888888")

    # Build findings HTML
    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev      = f.get("severity", "info").lower()
        color    = SEVERITY_COLORS.get(sev, "#888888")
        bg       = SEVERITY_BG.get(sev, "#1A1A1A")
        check    = f.get("check", "Unknown")
        detail   = f.get("detail", "")
        url      = f.get("url", "")
        module   = f.get("module", "")
        triage   = f.get("ai_triage", {})

        ai_section = ""
        if triage:
            powered    = "🤖 AI Powered" if triage.get("ai_powered") else "📋 Rule Based"
            score      = triage.get("risk_score", 0)
            score_color = SEVERITY_COLORS.get(
                "critical" if score >= 8 else
                "high"     if score >= 6 else
                "medium"   if score >= 4 else
                "low"      if score >= 2 else "info",
                "#888"
            )
            ai_section = f"""
            <div class="ai-triage">
                <div class="ai-header">
                    <span class="ai-badge">{powered}</span>
                    <span class="risk-score" style="color:{score_color}">
                        Risk Score: {score}/10
                    </span>
                </div>
                <p><strong>Explanation:</strong> {triage.get("explanation", "")}</p>
                <p><strong>Impact:</strong> {triage.get("impact", "")}</p>
                <div class="fix-box">
                    <strong>Fix:</strong> {triage.get("fix", "")}
                </div>
            </div>
            """

        url_html = f'<br><small><a href="{url}" style="color:#888">{url}</a></small>' if url else ""

        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}; background: {bg};">
            <div class="finding-header">
                <span class="finding-num">#{i}</span>
                <span class="severity-badge" style="background:{color}; color:#000">
                    {sev.upper()}
                </span>
                <span class="module-badge">{module.upper()}</span>
                <span class="finding-title">{check}</span>
            </div>
            <p class="finding-detail">{detail}{url_html}</p>
            {ai_section}
        </div>
        """

    # Summary cards
    summary_cards = ""
    for sev, count in counts.items():
        color = SEVERITY_COLORS.get(sev, "#888")
        summary_cards += f"""
        <div class="summary-card" style="border-top: 3px solid {color}">
            <div class="summary-count" style="color:{color}">{count}</div>
            <div class="summary-label">{sev.upper()}</div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HawkEye Security Report — {target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0D0D0D;
            color: #E0E0E0;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #0D1B2A, #1B2838);
            border-bottom: 2px solid #00FFFF;
            padding: 2rem 3rem;
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .logo {{
            font-size: 2rem;
            font-weight: bold;
            color: #00FFFF;
            letter-spacing: 4px;
        }}
        .logo span {{ color: #888; font-size: 0.9rem; display: block; letter-spacing: 1px; }}
        .risk-banner {{
            text-align: right;
        }}
        .risk-label {{
            font-size: 0.8rem;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        .risk-value {{
            font-size: 2rem;
            font-weight: bold;
            color: {risk_color};
        }}
        .target-info {{
            margin-top: 1.5rem;
            padding-top: 1rem;
            border-top: 1px solid #1E3A4A;
        }}
        .target-info table {{ border-collapse: collapse; }}
        .target-info td {{
            padding: 4px 20px 4px 0;
            color: #888;
            font-size: 0.9rem;
        }}
        .target-info td:last-child {{ color: #E0E0E0; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem 3rem; }}
        .section-title {{
            font-size: 1.1rem;
            color: #00FFFF;
            text-transform: uppercase;
            letter-spacing: 3px;
            margin: 2rem 0 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #1E3A4A;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: #111;
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }}
        .summary-count {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        .summary-label {{
            font-size: 0.75rem;
            color: #888;
            letter-spacing: 2px;
            margin-top: 4px;
        }}
        .finding {{
            border-radius: 8px;
            padding: 1.2rem 1.5rem;
            margin-bottom: 1rem;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 0.75rem;
        }}
        .finding-num {{
            color: #555;
            font-size: 0.85rem;
            min-width: 28px;
        }}
        .severity-badge {{
            font-size: 0.7rem;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 4px;
            letter-spacing: 1px;
        }}
        .module-badge {{
            font-size: 0.7rem;
            background: #1E3A4A;
            color: #00FFFF;
            padding: 2px 8px;
            border-radius: 4px;
        }}
        .finding-title {{
            font-weight: 500;
            font-size: 0.95rem;
        }}
        .finding-detail {{
            color: #AAA;
            font-size: 0.9rem;
            margin-left: 38px;
        }}
        .ai-triage {{
            margin: 1rem 0 0 38px;
            background: #111;
            border-radius: 6px;
            padding: 1rem;
            border: 1px solid #1E3A4A;
        }}
        .ai-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.75rem;
        }}
        .ai-badge {{
            font-size: 0.8rem;
            color: #00FFFF;
            background: #001D2D;
            padding: 2px 10px;
            border-radius: 4px;
        }}
        .risk-score {{
            font-weight: bold;
            font-size: 0.9rem;
        }}
        .fix-box {{
            background: #0D1B0D;
            border: 1px solid #1A3A1A;
            border-radius: 4px;
            padding: 0.75rem;
            margin-top: 0.75rem;
            font-size: 0.85rem;
            color: #90EE90;
        }}
        .ai-triage p {{
            font-size: 0.85rem;
            color: #CCC;
            margin-bottom: 0.5rem;
        }}
        .footer {{
            text-align: center;
            padding: 2rem;
            color: #444;
            font-size: 0.8rem;
            border-top: 1px solid #1E3A4A;
            margin-top: 3rem;
        }}
        @media print {{
            body {{ background: white; color: black; }}
            .header {{ background: #f5f5f5; border-color: #333; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-top">
            <div>
                <div class="logo">🦅 HAWKEYE
                    <span>AI-Assisted Bug Hunting Framework v1.0.0</span>
                </div>
            </div>
            <div class="risk-banner">
                <div class="risk-label">Overall Risk</div>
                <div class="risk-value">{risk_level}</div>
            </div>
        </div>
        <div class="target-info">
            <table>
                <tr>
                    <td>Target</td>
                    <td>{target or "N/A"}</td>
                </tr>
                <tr>
                    <td>Generated</td>
                    <td>{timestamp}</td>
                </tr>
                <tr>
                    <td>Total Findings</td>
                    <td>{len(findings)}</td>
                </tr>
                <tr>
                    <td>Tool</td>
                    <td>HawkEye v1.0.0 — Built by Kalpin Patel</td>
                </tr>
            </table>
        </div>
    </div>

    <div class="container">
        <div class="section-title">Executive Summary</div>
        <div class="summary-grid">
            {summary_cards}
        </div>

        <div class="section-title">Findings ({len(findings)})</div>
        {findings_html if findings_html else
         '<p style="color:#888">No findings to display.</p>'}
    </div>

    <div class="footer">
        Generated by HawkEye v1.0.0 · Built by Kalpin Patel · github.com/kalpin05
        <br>For authorized security testing only.
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


# ─────────────────────────────────────────
# PDF REPORT
# ─────────────────────────────────────────

def generate_pdf(findings: list, target: str = "",
                 output_path: str = "") -> str:
    """
    Generate PDF report.
    Uses WeasyPrint to convert HTML → PDF.
    Falls back to HTML if WeasyPrint not installed.
    """
    if not output_path:
        output_path = get_output_path(
            f"hawkeye_report_{get_filename_timestamp()}.pdf"
        )

    # First generate HTML
    html_path = output_path.replace(".pdf", "_temp.html")
    generate_html(findings, target, html_path)

    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(output_path)
        # Clean up temp HTML
        os.remove(html_path)
        return output_path
    except ImportError:
        # WeasyPrint not installed — save as HTML instead
        final_path = output_path.replace(".pdf", ".html")
        os.rename(html_path, final_path)
        return final_path
    except Exception as e:
        # WeasyPrint failed — return HTML
        final_path = output_path.replace(".pdf", ".html")
        if os.path.exists(html_path):
            os.rename(html_path, final_path)
        return final_path