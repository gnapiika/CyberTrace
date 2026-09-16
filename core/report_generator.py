import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
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
    correlations=None,
):
    """
    Generate a PDF investigation report for a CyberTrace case.

    The report contains:
    - Case information
    - Risk assessment
    - Evidence integrity
    - Suspicious activity alerts
    - Correlated activity
    - Investigation timeline
    - Investigation summary
    - Conclusion
    """

    if correlations is None:
        correlations = []

    output_directory = os.path.dirname(output_path)

    if output_directory:
        os.makedirs(
            output_directory,
            exist_ok=True,
        )

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CyberTraceTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "CyberTraceSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "CyberTraceHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "CyberTraceBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=6,
    )

    small_style = ParagraphStyle(
        "CyberTraceSmall",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        spaceAfter=3,
    )

    alert_style = ParagraphStyle(
        "CyberTraceAlert",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=12,
        spaceAfter=5,
    )

    story = []

    # ---------------------------------------------------------
    # TITLE
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "CyberTrace",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Digital Forensics Investigation Report",
            subtitle_style,
        )
    )

    # ---------------------------------------------------------
    # CASE INFORMATION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "1. Case Information",
            heading_style,
        )
    )

    case_data = [
        [
            Paragraph("<b>Case ID</b>", body_style),
            Paragraph(str(case.case_id), body_style),
        ],
        [
            Paragraph("<b>Case Name</b>", body_style),
            Paragraph(str(case.case_name), body_style),
        ],
        [
            Paragraph("<b>Status</b>", body_style),
            Paragraph(str(case.status), body_style),
        ],
        [
            Paragraph("<b>Created At</b>", body_style),
            Paragraph(str(case.created_at), body_style),
        ],
        [
            Paragraph("<b>Description</b>", body_style),
            Paragraph(
                str(case.description or "No description provided."),
                body_style,
            ),
        ],
    ]

    case_table = Table(
        case_data,
        colWidths=[45 * mm, 130 * mm],
    )

    case_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
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

    story.append(case_table)
    story.append(Spacer(1, 8))

    # ---------------------------------------------------------
    # RISK ASSESSMENT
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "2. Risk Assessment",
            heading_style,
        )
    )

    risk_data = [
        [
            Paragraph("<b>Risk Score</b>", body_style),
            Paragraph(
                f"{risk_score}/100",
                body_style,
            ),
        ],
        [
            Paragraph("<b>Risk Level</b>", body_style),
            Paragraph(
                str(risk_level),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Total Alerts</b>", body_style),
            Paragraph(
                str(len(alerts)),
                body_style,
            ),
        ],
        [
            Paragraph("<b>Correlated Activity Groups</b>", body_style),
            Paragraph(
                str(len(correlations)),
                body_style,
            ),
        ],
    ]

    risk_table = Table(
        risk_data,
        colWidths=[70 * mm, 105 * mm],
    )

    risk_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey,
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
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
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

    story.append(risk_table)

    story.append(
        Spacer(1, 5)
    )

    story.append(
        Paragraph(
            (
                "Risk scores are heuristic indicators based on detected "
                "activity and should be validated by a qualified investigator. "
                "A suspicious event or alert does not by itself establish "
                "that malicious activity occurred."
            ),
            body_style,
        )
    )

    # ---------------------------------------------------------
    # EVIDENCE INTEGRITY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "3. Evidence Integrity",
            heading_style,
        )
    )

    if evidence:

        evidence_data = [
            [
                Paragraph("<b>Evidence ID</b>", small_style),
                Paragraph("<b>Filename</b>", small_style),
                Paragraph("<b>Type</b>", small_style),
                Paragraph("<b>Size</b>", small_style),
                Paragraph("<b>Integrity</b>", small_style),
            ]
        ]

        for item in evidence:

            evidence_data.append(
                [
                    Paragraph(
                        str(item.evidence_id),
                        small_style,
                    ),
                    Paragraph(
                        str(item.filename),
                        small_style,
                    ),
                    Paragraph(
                        str(item.evidence_type),
                        small_style,
                    ),
                    Paragraph(
                        f"{item.file_size} bytes",
                        small_style,
                    ),
                    Paragraph(
                        str(item.integrity_status),
                        small_style,
                    ),
                ]
            )

        evidence_table = Table(
            evidence_data,
            colWidths=[
                32 * mm,
                55 * mm,
                25 * mm,
                28 * mm,
                35 * mm,
            ],
            repeatRows=1,
        )

        evidence_table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey,
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
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
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        story.append(evidence_table)
        story.append(Spacer(1, 8))

        story.append(
            Paragraph(
                "<b>SHA-256 Hashes</b>",
                body_style,
            )
        )

        for item in evidence:

            story.append(
                Paragraph(
                    (
                        f"{item.filename}: "
                        f"{item.sha256_hash}"
                    ),
                    small_style,
                )
            )

    else:

        story.append(
            Paragraph(
                "No evidence records were available.",
                body_style,
            )
        )

    # ---------------------------------------------------------
    # SUSPICIOUS ACTIVITY ALERTS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "4. Suspicious Activity Alerts",
            heading_style,
        )
    )

    if alerts:

        for index, alert in enumerate(alerts, start=1):

            story.append(
                Paragraph(
                    (
                        f"<b>Alert {index}: "
                        f"{alert.alert_name}</b>"
                    ),
                    alert_style,
                )
            )

            story.append(
                Paragraph(
                    (
                        f"<b>Alert ID:</b> "
                        f"{alert.alert_id}<br/>"
                        f"<b>Rule:</b> "
                        f"{alert.rule_id}<br/>"
                        f"<b>Severity:</b> "
                        f"{alert.severity}<br/>"
                        f"<b>Timestamp:</b> "
                        f"{alert.timestamp}<br/>"
                        f"<b>Description:</b> "
                        f"{alert.description}"
                    ),
                    alert_style,
                )
            )

            story.append(
                Spacer(1, 4)
            )

    else:

        story.append(
            Paragraph(
                "No suspicious activity alerts were detected.",
                body_style,
            )
        )

    # ---------------------------------------------------------
    # CORRELATED ACTIVITY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "5. Correlated Activity",
            heading_style,
        )
    )

    if correlations:

        for index, correlation in enumerate(
            correlations,
            start=1,
        ):

            events_in_group = correlation.get(
                "events",
                [],
            )

            evidence_types = correlation.get(
                "evidence_types",
                [],
            )

            start_time = correlation.get(
                "start_time"
            )

            end_time = correlation.get(
                "end_time"
            )

            story.append(
                Paragraph(
                    (
                        f"<b>Correlation Group "
                        f"{index}</b>"
                    ),
                    body_style,
                )
            )

            story.append(
                Paragraph(
                    (
                        f"<b>Sources:</b> "
                        f"{', '.join(evidence_types)}<br/>"
                        f"<b>Start:</b> "
                        f"{start_time}<br/>"
                        f"<b>End:</b> "
                        f"{end_time}<br/>"
                        f"<b>Related Events:</b> "
                        f"{len(events_in_group)}"
                    ),
                    small_style,
                )
            )

            for event in events_in_group:

                story.append(
                    Paragraph(
                        (
                            f"{event.timestamp} — "
                            f"<b>{event.event_type}</b> — "
                            f"{event.description}"
                        ),
                        small_style,
                    )
                )

            story.append(
                Spacer(1, 6)
            )

    else:

        story.append(
            Paragraph(
                "No cross-source event correlations were identified.",
                body_style,
            )
        )

    # ---------------------------------------------------------
    # INVESTIGATION TIMELINE
    # ---------------------------------------------------------

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "6. Investigation Timeline",
            heading_style,
        )
    )

    if events:

        timeline_data = [
            [
                Paragraph("<b>Timestamp</b>", small_style),
                Paragraph("<b>Type</b>", small_style),
                Paragraph("<b>Description</b>", small_style),
            ]
        ]

        for event in events:

            timeline_data.append(
                [
                    Paragraph(
                        str(event.timestamp),
                        small_style,
                    ),
                    Paragraph(
                        str(event.event_type),
                        small_style,
                    ),
                    Paragraph(
                        str(event.description or ""),
                        small_style,
                    ),
                ]
            )

        timeline_table = Table(
            timeline_data,
            colWidths=[
                42 * mm,
                30 * mm,
                78 * mm,
            ],
            repeatRows=1,
        )

        timeline_table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey,
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
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
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        4,
                    ),
                ]
            )
        )

        story.append(
            timeline_table
        )

    else:

        story.append(
            Paragraph(
                "No events were available for the investigation timeline.",
                body_style,
            )
        )

    # ---------------------------------------------------------
    # INVESTIGATION SUMMARY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "7. Investigation Summary",
            heading_style,
        )
    )

    if events:

        first_event = events[0]
        last_event = events[-1]

        source_types = sorted(
            {
                event.event_type
                for event in events
                if event.event_type
            }
        )

        summary_text = (
            f"The investigation contains {len(events)} recorded events "
            f"across {len(source_types)} evidence source type(s). "
            f"The recorded activity begins at {first_event.timestamp} "
            f"and ends at {last_event.timestamp}. "
        )

        if source_types:

            summary_text += (
                "Evidence sources represented in the timeline include: "
                f"{', '.join(source_types)}. "
            )

        if alerts:

            summary_text += (
                f"The detection engine identified {len(alerts)} "
                "suspicious activity alert(s). "
            )

        else:

            summary_text += (
                "The detection engine did not identify any suspicious "
                "activity alerts. "
            )

        if correlations:

            summary_text += (
                f"{len(correlations)} cross-source correlation group(s) "
                "were identified for further investigation."
            )

        else:

            summary_text += (
                "No cross-source correlation groups were identified."
            )

        story.append(
            Paragraph(
                summary_text,
                body_style,
            )
        )

    else:

        story.append(
            Paragraph(
                "There were no recorded events available for analysis.",
                body_style,
            )
        )

    # ---------------------------------------------------------
    # CONCLUSION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "8. Conclusion",
            heading_style,
        )
    )

    conclusion_text = (
        "CyberTrace reconstructed the available forensic evidence into "
        "a chronological investigation timeline and applied deterministic "
        "detection and correlation rules. "
    )

    if alerts:

        conclusion_text += (
            f"The analysis produced {len(alerts)} suspicious activity "
            "alert(s), with a calculated heuristic risk score of "
            f"{risk_score}/100 ({risk_level}). "
        )

    else:

        conclusion_text += (
            "No suspicious activity alerts were produced by the current "
            "detection rules. "
        )

    conclusion_text += (
        "The findings should be treated as investigative indicators rather "
        "than definitive proof of malicious activity. Further validation "
        "using the original evidence and appropriate forensic procedures "
        "is recommended."
    )

    story.append(
        Paragraph(
            conclusion_text,
            body_style,
        )
    )

    # ---------------------------------------------------------
    # FOOTER / DISCLAIMER
    # ---------------------------------------------------------

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            (
                "<b>CyberTrace Investigation Report</b><br/>"
                "Generated automatically from the evidence available "
                "within the selected case.<br/>"
                "CyberTrace analyzes evidence and does not execute files "
                "contained within evidence packages."
            ),
            small_style,
        )
    )

    # ---------------------------------------------------------
    # BUILD PDF
    # ---------------------------------------------------------

    document.build(story)

    return output_path