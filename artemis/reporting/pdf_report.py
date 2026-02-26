"""PDF threat report generator for Artemis using ReportLab."""

import io
from datetime import datetime
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)


# Severity colour map
_SEV_COLORS = {
    'critical': colors.HexColor('#f85149'),
    'high': colors.HexColor('#db6d28'),
    'medium': colors.HexColor('#d29922'),
    'low': colors.HexColor('#58a6ff'),
    'info': colors.HexColor('#8b949e'),
}

# Dark theme colours
_BG = colors.HexColor('#0f1117')
_BG_CARD = colors.HexColor('#1a1d28')
_TEXT = colors.HexColor('#c9d1d9')
_TEXT_DIM = colors.HexColor('#8b949e')
_ACCENT = colors.HexColor('#58a6ff')
_BORDER = colors.HexColor('#30363d')


def _build_styles():
    """Build custom paragraph styles for the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'ReportTitle', parent=styles['Title'],
        fontSize=26, textColor=_TEXT, spaceAfter=6,
        alignment=1,  # CENTER
    ))
    styles.add(ParagraphStyle(
        'ReportSubtitle', parent=styles['Normal'],
        fontSize=13, textColor=_ACCENT, spaceAfter=4,
        alignment=1,
    ))
    styles.add(ParagraphStyle(
        'ReportDate', parent=styles['Normal'],
        fontSize=10, textColor=_TEXT_DIM, spaceAfter=12,
        alignment=1,
    ))
    styles.add(ParagraphStyle(
        'SectionHeader', parent=styles['Heading2'],
        fontSize=13, textColor=_ACCENT, spaceBefore=16,
        spaceAfter=8, borderWidth=0,
    ))
    styles.add(ParagraphStyle(
        'BodyText2', parent=styles['Normal'],
        fontSize=10, textColor=_TEXT, leading=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        'BodyDim', parent=styles['Normal'],
        fontSize=9, textColor=_TEXT_DIM, leading=12,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        'FindingTitle', parent=styles['Normal'],
        fontSize=10, textColor=_TEXT, leading=13,
        spaceAfter=3, fontName='Helvetica-Bold',
    ))
    styles.add(ParagraphStyle(
        'CodeText', parent=styles['Normal'],
        fontSize=8, textColor=_TEXT_DIM, leading=10,
        fontName='Courier', leftIndent=12,
    ))
    return styles


def _safe(text) -> str:
    """Escape text for ReportLab XML paragraphs."""
    if not isinstance(text, str):
        text = str(text)
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;'))


def generate_threat_report(
    synthesis: Optional[Dict],
    findings: List[Dict],
    findings_summary: Dict,
) -> bytes:
    """Generate a PDF threat intelligence report. Returns PDF as bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm,
        leftMargin=15 * mm, rightMargin=15 * mm,
        title='Artemis Threat Intelligence Report',
        author='Artemis Platform',
    )

    styles = _build_styles()
    story = []

    # ── Title ──────────────────────────────────────────────
    story.append(Spacer(1, 30))
    story.append(Paragraph('ARTEMIS', styles['ReportTitle']))
    story.append(Paragraph('Threat Intelligence Report', styles['ReportSubtitle']))
    story.append(Paragraph(
        f'Generated: {datetime.now().strftime("%B %d, %Y at %H:%M UTC")}',
        styles['ReportDate'],
    ))

    # Severity headline
    if synthesis:
        sev = (synthesis.get('overall_severity') or 'unknown').lower()
        conf = synthesis.get('overall_confidence', 0)
        full = synthesis.get('full_synthesis', synthesis)
        sev_color = _SEV_COLORS.get(sev, _TEXT_DIM)
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f'<font color="{sev_color.hexval()}"><b>Overall Threat Level: '
            f'{sev.upper()}</b></font>  '
            f'<font color="{_TEXT_DIM.hexval()}">'
            f'({conf:.0%} confidence)</font>',
            ParagraphStyle('sev_head', parent=styles['ReportSubtitle'],
                           fontSize=12, textColor=_TEXT),
        ))
    else:
        full = {}

    # Findings summary line
    total_findings = findings_summary.get('total', len(findings))
    by_sev = findings_summary.get('by_severity', {})
    sev_parts = []
    for s in ('critical', 'high', 'medium', 'low'):
        c = by_sev.get(s, 0)
        if c:
            sc = _SEV_COLORS.get(s, _TEXT_DIM)
            sev_parts.append(f'<font color="{sc.hexval()}">{c} {s}</font>')
    line = f'{total_findings} total findings'
    if sev_parts:
        line += f' ({", ".join(sev_parts)})'
    story.append(Paragraph(line, styles['ReportDate']))

    story.append(HRFlowable(width='100%', color=_BORDER, thickness=1,
                             spaceBefore=10, spaceAfter=10))

    # ── Executive Summary ──────────────────────────────────
    if synthesis:
        reasoning = full.get('reasoning', '') or synthesis.get('reasoning', '')
        if reasoning:
            story.append(Paragraph('EXECUTIVE SUMMARY', styles['SectionHeader']))
            story.append(Paragraph(_safe(reasoning), styles['BodyText2']))

        # Kill Chain Assessment
        kc = (full.get('kill_chain_assessment') or full.get('kill_chain')
              or synthesis.get('kill_chain', {}))
        stages = kc.get('stages', []) if isinstance(kc, dict) else []
        if stages:
            story.append(Paragraph('KILL CHAIN ASSESSMENT', styles['SectionHeader']))
            kc_data = [['Stage', 'Status', 'Evidence']]
            for st in stages:
                if isinstance(st, dict):
                    name = st.get('stage', st.get('name', ''))
                    status = st.get('status', st.get('active', ''))
                    evidence = st.get('evidence', '')
                    if isinstance(evidence, list):
                        evidence = ', '.join(str(e) for e in evidence)
                    kc_data.append([name, str(status), str(evidence)[:80]])
                elif isinstance(st, str):
                    kc_data.append([st, '', ''])
            if len(kc_data) > 1:
                t = Table(kc_data, colWidths=[45 * mm, 35 * mm, None])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), _BG_CARD),
                    ('TEXTCOLOR', (0, 0), (-1, 0), _ACCENT),
                    ('TEXTCOLOR', (0, 1), (-1, -1), _TEXT),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 0.5, _BORDER),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(t)
            progression = kc.get('progression', '') if isinstance(kc, dict) else ''
            if progression:
                story.append(Spacer(1, 6))
                story.append(Paragraph(
                    f'<b>Progression:</b> {_safe(str(progression))}',
                    styles['BodyDim'],
                ))

        # Correlations
        correlations = (full.get('correlations') or
                        synthesis.get('correlations', []))
        if correlations:
            story.append(Paragraph('CROSS-AGENT CORRELATIONS', styles['SectionHeader']))
            for i, corr in enumerate(correlations, 1):
                if isinstance(corr, dict):
                    desc = corr.get('description', '')
                    agents = corr.get('agents_involved', [])
                    cconf = corr.get('confidence', 0)
                    story.append(Paragraph(
                        f'<b>{i}.</b> {_safe(desc)}', styles['BodyText2']))
                    if agents:
                        story.append(Paragraph(
                            f'Agents: {", ".join(agents)}  |  '
                            f'Confidence: {cconf:.0%}',
                            styles['BodyDim']))
                else:
                    story.append(Paragraph(
                        f'<b>{i}.</b> {_safe(str(corr))}', styles['BodyText2']))

        # False Positive Flags
        fp_flags = (full.get('false_positive_flags') or
                    synthesis.get('false_positive_flags', []))
        if fp_flags:
            story.append(Paragraph('FALSE POSITIVE FLAGS', styles['SectionHeader']))
            for fp in fp_flags:
                text = (fp.get('description', fp.get('finding', str(fp)))
                        if isinstance(fp, dict) else str(fp))
                story.append(Paragraph(
                    f'<font color="{_SEV_COLORS["medium"].hexval()}">'
                    f'&#9888;</font> {_safe(text)}',
                    styles['BodyText2']))

        # Recommended Actions
        actions = (full.get('recommended_actions') or
                   synthesis.get('recommended_actions', []))
        if actions:
            story.append(Paragraph('RECOMMENDED ACTIONS', styles['SectionHeader']))
            for i, action in enumerate(actions, 1):
                if isinstance(action, dict):
                    act = action.get('action', '')
                    pri = (action.get('priority', '') or '').lower()
                    timeline = action.get('timeline', '')
                    affected = action.get('affected_assets', [])
                    pc = _SEV_COLORS.get(pri, _TEXT)
                    story.append(Paragraph(
                        f'<b>{i}.</b> '
                        f'<font color="{pc.hexval()}">[{pri.upper() or "ACTION"}]</font> '
                        f'{_safe(act)}',
                        styles['BodyText2']))
                    parts = []
                    if timeline:
                        parts.append(f'Timeline: {timeline}')
                    if affected:
                        assets = affected if isinstance(affected, list) else [affected]
                        parts.append(f'Assets: {", ".join(str(a) for a in assets[:5])}')
                    if parts:
                        story.append(Paragraph(
                            ' | '.join(parts), styles['BodyDim']))
                else:
                    story.append(Paragraph(
                        f'<b>{i}.</b> {_safe(str(action))}',
                        styles['BodyText2']))

    # ── Agent Findings ─────────────────────────────────────
    if findings:
        story.append(PageBreak())
        story.append(Paragraph(
            f'AGENT FINDINGS ({len(findings)})', styles['SectionHeader']))

        for f in findings[:50]:
            sev = (f.get('severity') or 'medium').lower()
            sc = _SEV_COLORS.get(sev, _TEXT_DIM)
            agent = f.get('agent_name', 'unknown')
            activity = f.get('activity_type', '')

            story.append(Paragraph(
                f'<font color="{sc.hexval()}"><b>[{sev.upper()}]</b></font> '
                f'{_safe(activity)}  '
                f'<font color="{_TEXT_DIM.hexval()}">({_safe(agent)})</font>',
                styles['FindingTitle']))

            desc = f.get('description', '')
            if desc:
                if len(desc) > 400:
                    desc = desc[:400] + '...'
                story.append(Paragraph(_safe(desc), styles['BodyDim']))

            techniques = f.get('mitre_techniques', [])
            if techniques:
                story.append(Paragraph(
                    f'<font color="{_ACCENT.hexval()}">MITRE: '
                    f'{", ".join(techniques[:5])}</font>',
                    styles['BodyDim']))

            indicators = f.get('indicators', [])
            if indicators:
                for ind in indicators[:3]:
                    ind_text = (str(ind) if not isinstance(ind, dict)
                                else ind.get('value', str(ind)))
                    if len(ind_text) > 80:
                        ind_text = ind_text[:80] + '...'
                    story.append(Paragraph(_safe(ind_text), styles['CodeText']))

            story.append(Spacer(1, 6))

    doc.build(story)
    return buf.getvalue()
