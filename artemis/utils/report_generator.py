"""
Report generator for Artemis hunt results.

Produces self-contained HTML reports from hunt data stored in the database.
"""

from datetime import datetime
from typing import Dict, List, Any
from html import escape


def generate_html_report(hunt: Dict[str, Any]) -> str:
    """
    Generate a self-contained HTML report for a hunt.

    Args:
        hunt: Hunt details dict from DatabaseManager.get_hunt_details()

    Returns:
        Complete HTML string
    """
    hunt_id = escape(hunt.get('hunt_id', 'Unknown'))
    time_range = escape(str(hunt.get('time_range', 'N/A')))
    mode = escape(str(hunt.get('mode', 'N/A')))
    status = escape(str(hunt.get('status', 'N/A')))
    description = escape(str(hunt.get('description', '') or ''))
    start_time = escape(str(hunt.get('start_time', 'N/A')))
    end_time = escape(str(hunt.get('end_time', 'N/A')))
    total_findings = hunt.get('total_findings', 0)
    overall_confidence = hunt.get('overall_confidence', 0.0)

    findings = hunt.get('findings', [])
    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    # Group findings by severity
    severity_order = ['critical', 'high', 'medium', 'low']
    grouped: Dict[str, List] = {s: [] for s in severity_order}
    for f in findings:
        sev = (f.get('severity') or 'low').lower()
        if sev not in grouped:
            sev = 'low'
        grouped[sev].append(f)

    # Collect all MITRE techniques across findings
    all_techniques = set()
    all_tactics = set()
    for f in findings:
        for t in (f.get('mitre_techniques') or []):
            all_techniques.add(t)
        for t in (f.get('mitre_tactics') or []):
            all_tactics.add(t)

    # Build findings HTML
    findings_html = ""
    severity_colors = {
        'critical': '#f85149',
        'high': '#d29922',
        'medium': '#58a6ff',
        'low': '#8b949e',
    }

    for sev in severity_order:
        items = grouped[sev]
        if not items:
            continue
        color = severity_colors[sev]
        findings_html += f'<h3 style="color:{color}; margin-top:24px;">{sev.upper()} ({len(items)})</h3>\n'
        for f in items:
            title = escape(f.get('title') or 'Untitled')
            desc = escape(f.get('description') or '')
            agent = escape(f.get('agent_name') or 'unknown')
            conf = f.get('confidence', 0.0)
            techniques = f.get('mitre_techniques') or []
            tactics = f.get('mitre_tactics') or []
            assets = f.get('affected_assets') or []

            techniques_html = ""
            if techniques:
                techniques_html = f'<div class="meta">MITRE Techniques: {escape(", ".join(techniques))}</div>'
            tactics_html = ""
            if tactics:
                tactics_html = f'<div class="meta">MITRE Tactics: {escape(", ".join(tactics))}</div>'
            assets_html = ""
            if assets:
                assets_html = f'<div class="meta">Affected Assets: {escape(", ".join(assets))}</div>'

            findings_html += f"""
            <div class="finding" style="border-left-color:{color};">
                <div class="finding-title">{title}</div>
                <div class="finding-desc">{desc}</div>
                <div class="meta">Agent: {agent} | Confidence: {conf:.2f}</div>
                {techniques_html}
                {tactics_html}
                {assets_html}
            </div>
            """

    if not findings:
        findings_html = '<p style="color:#3fb950;">No findings - network appears clean.</p>'

    # MITRE summary
    mitre_html = ""
    if all_techniques:
        mitre_html = '<h2>MITRE ATT&CK Coverage</h2><div class="mitre-grid">'
        for t in sorted(all_techniques):
            mitre_html += f'<span class="mitre-tag">{escape(t)}</span>'
        mitre_html += '</div>'
    if all_tactics:
        mitre_html += '<div class="mitre-grid" style="margin-top:8px;">'
        for t in sorted(all_tactics):
            mitre_html += f'<span class="mitre-tag tactic">{escape(t)}</span>'
        mitre_html += '</div>'

    # Confidence gauge color
    if overall_confidence >= 0.9:
        conf_color = '#f85149'
        alert_level = 'CRITICAL'
    elif overall_confidence >= 0.7:
        conf_color = '#d29922'
        alert_level = 'HIGH'
    elif overall_confidence >= 0.5:
        conf_color = '#58a6ff'
        alert_level = 'MEDIUM'
    else:
        conf_color = '#3fb950'
        alert_level = 'LOW'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Artemis Hunt Report - {hunt_id}</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        background: #0f1117;
        color: #c9d1d9;
        line-height: 1.6;
        padding: 0;
        margin: 0;
    }}
    .container {{
        max-width: 900px;
        margin: 0 auto;
        padding: 40px 20px;
    }}
    h1 {{
        font-size: 1.8em;
        margin-bottom: 4px;
    }}
    h2 {{
        font-size: 1.3em;
        margin-top: 32px;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid #30363d;
    }}
    .subtitle {{
        color: #8b949e;
        font-size: 0.9em;
        margin-bottom: 24px;
    }}
    .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-bottom: 24px;
    }}
    .summary-card {{
        background: #1a1d28;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 16px;
        text-align: center;
    }}
    .summary-card .value {{
        font-size: 1.8em;
        font-weight: 700;
    }}
    .summary-card .label {{
        color: #8b949e;
        font-size: 0.85em;
        margin-top: 4px;
    }}
    .finding {{
        background: #1a1d28;
        border-left: 4px solid #8b949e;
        border-radius: 0 6px 6px 0;
        padding: 14px 16px;
        margin-bottom: 10px;
    }}
    .finding-title {{
        font-weight: 600;
        font-size: 1em;
        margin-bottom: 4px;
    }}
    .finding-desc {{
        color: #c9d1d9;
        margin-bottom: 6px;
        font-size: 0.9em;
    }}
    .meta {{
        color: #8b949e;
        font-size: 0.82em;
    }}
    .mitre-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
    }}
    .mitre-tag {{
        background: #242836;
        border: 1px solid #30363d;
        border-radius: 4px;
        padding: 4px 10px;
        font-size: 0.82em;
        font-family: monospace;
    }}
    .mitre-tag.tactic {{
        border-color: #58a6ff;
        color: #58a6ff;
    }}
    .info-table {{
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 20px;
    }}
    .info-table td {{
        padding: 6px 12px;
        border-bottom: 1px solid #242836;
        font-size: 0.9em;
    }}
    .info-table td:first-child {{
        color: #8b949e;
        width: 180px;
        font-weight: 500;
    }}
    .footer {{
        margin-top: 40px;
        padding-top: 16px;
        border-top: 1px solid #30363d;
        color: #8b949e;
        font-size: 0.8em;
        text-align: center;
    }}
    @media print {{
        body {{ background: #fff; color: #1f2328; }}
        .container {{ max-width: 100%; }}
        .summary-card {{ background: #f6f8fa; border-color: #d0d7de; }}
        .finding {{ background: #f6f8fa; }}
        .mitre-tag {{ background: #f6f8fa; border-color: #d0d7de; }}
    }}
</style>
</head>
<body>
<div class="container">
    <h1>Artemis Threat Hunt Report</h1>
    <div class="subtitle">Generated {generated_at}</div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="value" style="color:{conf_color};">{overall_confidence:.2f}</div>
            <div class="label">Overall Confidence</div>
        </div>
        <div class="summary-card">
            <div class="value" style="color:{conf_color};">{alert_level}</div>
            <div class="label">Alert Level</div>
        </div>
        <div class="summary-card">
            <div class="value">{total_findings}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="summary-card">
            <div class="value">{len(all_techniques)}</div>
            <div class="label">MITRE Techniques</div>
        </div>
    </div>

    <h2>Hunt Details</h2>
    <table class="info-table">
        <tr><td>Hunt ID</td><td>{hunt_id}</td></tr>
        <tr><td>Time Range</td><td>{time_range}</td></tr>
        <tr><td>Mode</td><td>{mode}</td></tr>
        <tr><td>Status</td><td>{status}</td></tr>
        <tr><td>Start Time</td><td>{start_time}</td></tr>
        <tr><td>End Time</td><td>{end_time}</td></tr>
        {"<tr><td>Description</td><td>" + description + "</td></tr>" if description else ""}
    </table>

    {mitre_html}

    <h2>Findings ({total_findings})</h2>
    {findings_html}

    <div class="footer">
        Artemis Threat Hunting Platform &mdash; Report generated {generated_at}
    </div>
</div>
</body>
</html>"""
