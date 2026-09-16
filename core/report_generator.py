import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def generate_investigation_report(
    case,
    evidence,
    events,
    alerts,
    risk_score,
    risk_level,
    output_path,
):
    """
    Generate a PDF investigation report for a CyberTrace case.
    """

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        spaceBefore=14,
        spaceAfter=10,
    )

    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        spaceAfter=6,
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
    )

    alert_style = ParagraphStyle(
        "AlertText",
        parent=normal_style,
        fontSize=8.5,
        leading=12,
    )

    story = []

    # ==========================================================
    # TITLE
    # ==========================================================

    story.append(Paragraph("CyberTrace", title_style))
    story.append(
        Paragraph(
            "Digital Forensics Investigation Report",
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            "Evidence-based analysis of digital activity. "
            "Suspicious events identified by CyberTrace are "
            "heuristic findings and require investigator validation.",
            normal_style,
        )
    )

    story.append(Spacer(1, 8))

    # ==========================================================
    # CASE INFORMATION
    # ==========================================================

    story.append(
        Paragraph(
            "1. Case Information",
            heading_style,
        )
    )

    case_data = [
        ["Case ID", case.case_id],
        ["Case Name", case.case_name],
        ["Status", case.status or "Open"],
        [
            "Created",
            case.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if case.created_at
            else "N/A",
        ],
        [
            "Description",
            case.description or "No description provided.",
        ],
    ]

    case_table = Table(
        case_data,
        colWidths=[42 * mm, 125 * mm],
    )

    case_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeeb")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(case_table)

    # ==========================================================
    # RISK ASSESSMENT
    # ==========================================================

    story.append(
        Paragraph(
            "2. Risk Assessment",
            heading_style,
        )
    )

    risk_data = [
        ["Risk Score", f"{risk_score}/100"],
        ["Risk Level", risk_level],
        ["Total Events", str(len(events))],
        ["Suspicious Alerts", str(len(alerts))],
    ]

    risk_table = Table(
        risk_data,
        colWidths=[55 * mm, 112 * mm],
    )

    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeeb")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(risk_table)

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            "Risk score interpretation: LOW (0–20), "
            "MODERATE (21–40), MEDIUM (41–60), "
            "HIGH (61–80), CRITICAL (81–100).",
            small_style,
        )
    )

    # ==========================================================
    # EVIDENCE
    # ==========================================================

    story.append(
        Paragraph(
            "3. Evidence Integrity",
            heading_style,
        )
    )

    if evidence:
        evidence_data = [
            [
                "Evidence ID",
                "Filename",
                "Type",
                "Size",
                "Integrity",
            ]
        ]

        for item in evidence:
            evidence_data.append(
                [
                    item.evidence_id,
                    item.filename,
                    item.evidence_type,
                    f"{item.file_size} bytes",
                    item.integrity_status,
                ]
            )

        evidence_table = Table(
            evidence_data,
            colWidths=[
                29 * mm,
                43 * mm,
                22 * mm,
                28 * mm,
                35 * mm,
            ],
            repeatRows=1,
        )

        evidence_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#292929"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTNAME",
                        (0, 1),
                        (-1, -1),
                        "Helvetica",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#dddddd"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        story.append(evidence_table)

        story.append(Spacer(1, 8))

        for item in evidence:
            story.append(
                Paragraph(
                    f"<b>{item.evidence_id}</b> — "
                    f"SHA-256: {item.sha256_hash}",
                    small_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "No evidence has been associated with this case.",
                normal_style,
            )
        )

    # ==========================================================
    # ALERTS
    # ==========================================================

    story.append(
        Paragraph(
            "4. Suspicious Activity Alerts",
            heading_style,
        )
    )

    if alerts:
        for index, alert in enumerate(alerts, start=1):
            timestamp = (
                alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if alert.timestamp
                else "N/A"
            )

            story.append(
                Paragraph(
                    f"<b>Alert {index}: {alert.alert_name}</b>",
                    alert_style,
                )
            )

            story.append(
                Paragraph(
                    f"Rule: {alert.rule_id}<br/>"
                    f"Severity: {alert.severity}<br/>"
                    f"Timestamp: {timestamp}<br/>"
                    f"Description: {alert.description}",
                    alert_style,
                )
            )

            story.append(Spacer(1, 6))
    else:
        story.append(
            Paragraph(
                "No suspicious activity alerts were detected.",
                normal_style,
            )
        )

    # ==========================================================
    # TIMELINE
    # ==========================================================

    story.append(
        Paragraph(
            "5. Investigation Timeline",
            heading_style,
        )
    )

    if events:
        timeline_data = [
            [
                "Timestamp",
                "Type",
                "Severity",
                "Description",
            ]
        ]

        for event in events:
            timestamp = (
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if event.timestamp
                else "N/A"
            )

            description = event.description or ""

            timeline_data.append(
                [
                    timestamp,
                    event.event_type,
                    event.severity or "INFO",
                    Paragraph(
                        description,
                        small_style,
                    ),
                ]
            )

        timeline_table = Table(
            timeline_data,
            colWidths=[
                35 * mm,
                25 * mm,
                25 * mm,
                82 * mm,
            ],
            repeatRows=1,
        )

        timeline_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#292929"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    (
                        "FONTNAME",
                        (0, 1),
                        (-1, -1),
                        "Helvetica",
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#dddddd"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(timeline_table)
    else:
        story.append(
            Paragraph(
                "No events are currently available for this case.",
                normal_style,
            )
        )

    # ==========================================================
    # INVESTIGATION SUMMARY
    # ==========================================================

    story.append(
        Paragraph(
            "6. Investigation Summary",
            heading_style,
        )
    )

    if alerts:
        summary_text = (
            f"CyberTrace processed {len(events)} event(s) associated with "
            f"case {case.case_id}. The analysis identified {len(alerts)} "
            f"suspicious activity alert(s). The resulting heuristic risk "
            f"score is {risk_score}/100, categorized as {risk_level}. "
            "These findings represent automated indicators and should "
            "be reviewed by an investigator together with the underlying "
            "evidence."
        )
    else:
        summary_text = (
            f"CyberTrace processed {len(events)} event(s) associated with "
            f"case {case.case_id}. No suspicious activity alerts were "
            "generated by the configured detection rules. This does not "
            "establish that no malicious activity occurred; it only "
            "indicates that the implemented detection rules did not "
            "identify a matching suspicious pattern."
        )

    story.append(
        Paragraph(
            summary_text,
            normal_style,
        )
    )

    # ==========================================================
    # CONCLUSION
    # ==========================================================

    story.append(
        Paragraph(
            "7. Conclusion",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            "This report documents the results produced by the CyberTrace "
            "digital forensics analysis pipeline. The platform preserves "
            "the original uploaded evidence, calculates SHA-256 integrity "
            "hashes, parses supported evidence sources, normalizes events, "
            "constructs a chronological timeline, and applies rule-based "
            "detection logic.",
            normal_style,
        )
    )

    story.append(
        Paragraph(
            "Automated alerts are indicators for further investigation "
            "and should not be treated as definitive proof of malicious "
            "activity. Investigators should validate findings against "
            "the original evidence and relevant forensic procedures.",
            normal_style,
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Generated by CyberTrace Digital Forensics Investigation Platform",
            small_style,
        )
    )

    document.build(story)

    return output_path