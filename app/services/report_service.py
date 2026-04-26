"""PDF incident report generation for Central Bank of Uzbekistan."""

import io
import logging
import smtplib
import uuid
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage,
    HRFlowable,
)

from app.config import settings
from app.models.threat import Threat
from app.models.ai_analysis import AIAnalysis
from app.services.storage_service import upload_file, download_file

logger = logging.getLogger(__name__)


def _build_styles():
    """Build custom report styles."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=18,
        textColor=HexColor("#1a1a2e"),
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=HexColor("#16213e"),
        spaceBefore=14,
        spaceAfter=6,
        borderWidth=0,
    ))
    styles.add(ParagraphStyle(
        "FieldLabel",
        parent=styles["Normal"],
        fontSize=9,
        textColor=HexColor("#666666"),
    ))
    styles.add(ParagraphStyle(
        "FieldValue",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#1a1a2e"),
        spaceBefore=1,
        spaceAfter=6,
    ))
    return styles


def generate_incident_report(
    threat: Threat,
    analysis: AIAnalysis | None = None,
    screenshot_bytes: bytes | None = None,
) -> bytes:
    """Generate a PDF incident report and return the raw bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
    )
    styles = _build_styles()
    story = []

    # -- Header --
    story.append(Paragraph("XAVFSIZLIK INTSIDENTI HISOBOTI", styles["ReportTitle"]))
    story.append(Paragraph(
        "O'zbekiston Respublikasi Markaziy Banki Kiberxavfsizlik bo'limiga",
        styles["FieldLabel"],
    ))
    story.append(Paragraph(
        f"SafeTalk DRP · Hisobot raqami: ST-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
        styles["FieldLabel"],
    ))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#cccccc")))
    story.append(Spacer(1, 10))

    # -- Threat Summary --
    story.append(Paragraph("1. Tahdid ma'lumotlari", styles["SectionHeader"]))

    threat_data = [
        ["Maydon", "Qiymat"],
        ["Tahdid ID", str(threat.id)],
        ["Aniqlangan URL", threat.detected_url or "—"],
        ["Manba", threat.source.value],
        ["Risk ball", f"{threat.risk_score}/100"],
        ["Label", threat.label.value],
        ["Jo'natuvchi", threat.sender_name or "—"],
        ["Ilova", threat.source_app or "—"],
        ["Aniqlangan sana", threat.received_at.strftime("%Y-%m-%d %H:%M UTC") if threat.received_at else "—"],
        ["Holat", threat.status.value],
    ]

    t = Table(threat_data, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ("BACKGROUND", (0, 1), (0, -1), HexColor("#f0f0f5")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # -- Message Text --
    if threat.message_truncated:
        story.append(Paragraph("2. Xabar matni", styles["SectionHeader"]))
        story.append(Paragraph(threat.message_truncated, styles["FieldValue"]))

    # -- Screenshot --
    if screenshot_bytes:
        story.append(Paragraph("3. Veb-sayt skrinshoti", styles["SectionHeader"]))
        try:
            img_buf = io.BytesIO(screenshot_bytes)
            img = RLImage(img_buf, width=160 * mm, height=90 * mm, kind="proportional")
            story.append(img)
        except Exception as e:
            story.append(Paragraph(f"(Skrinshotni yuklashda xatolik: {e})", styles["FieldLabel"]))
        story.append(Spacer(1, 8))

    # -- AI Analysis --
    if analysis:
        section_num = 4 if screenshot_bytes else 3
        story.append(Paragraph(f"{section_num}. AI tahlil natijalari", styles["SectionHeader"]))

        ai_data = [
            ["Maydon", "Qiymat"],
            ["Jiddiylik darajasi", (analysis.severity_assessment or "—").upper()],
            ["Tahdid turi", analysis.threat_type or "—"],
            ["Ishonch bali", f"{analysis.confidence_score}%" if analysis.confidence_score else "—"],
        ]
        at = Table(ai_data, colWidths=[45 * mm, 120 * mm])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("BACKGROUND", (0, 1), (0, -1), HexColor("#f0f0f5")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(at)

        story.append(Paragraph("Batafsil tahlil:", styles["FieldLabel"]))
        story.append(Paragraph(analysis.analysis_text, styles["FieldValue"]))

        if analysis.recommended_actions:
            story.append(Paragraph("Tavsiya etilgan choralar:", styles["FieldLabel"]))
            for action in analysis.recommended_actions:
                story.append(Paragraph(f"• {action}", styles["FieldValue"]))

        if analysis.ioc_indicators:
            iocs = analysis.ioc_indicators
            story.append(Paragraph("IOC indikatorlari:", styles["FieldLabel"]))
            for key, vals in iocs.items():
                if vals:
                    story.append(Paragraph(f"  {key}: {', '.join(str(v) for v in vals)}", styles["FieldValue"]))

    # -- Reasons & Tags --
    section_num = (5 if screenshot_bytes else 4) if analysis else (4 if screenshot_bytes else 3)
    story.append(Paragraph(f"{section_num}. Qo'shimcha ma'lumotlar", styles["SectionHeader"]))
    if threat.reasons:
        story.append(Paragraph("Sabablar:", styles["FieldLabel"]))
        for r in threat.reasons:
            story.append(Paragraph(f"• {r}", styles["FieldValue"]))
    if threat.auto_tags:
        story.append(Paragraph(f"Auto teglar: {', '.join(threat.auto_tags)}", styles["FieldValue"]))
    if threat.manual_tags:
        story.append(Paragraph(f"Qo'lda teglar: {', '.join(threat.manual_tags)}", styles["FieldValue"]))

    # -- Footer --
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#cccccc")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Bu hisobot SafeTalk DRP tizimi tomonidan avtomatik tarzda yaratilgan. "
        f"Sana: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        styles["FieldLabel"],
    ))

    doc.build(story)
    return buf.getvalue()


async def generate_and_send_report(
    threat: Threat,
    analysis: AIAnalysis | None = None,
    requested_by_name: str = "SafeTalk Admin",
) -> dict:
    """Generate PDF report, upload to MinIO, and send via email to Central Bank."""

    # Load screenshot if available
    screenshot_bytes = None
    if threat.screenshot_key:
        try:
            screenshot_bytes = download_file(threat.screenshot_key)
        except Exception as e:
            logger.warning(f"Could not load screenshot for report: {e}")

    # Generate PDF
    pdf_bytes = generate_incident_report(threat, analysis, screenshot_bytes)

    # Upload to MinIO
    report_key = f"reports/{threat.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    upload_file(report_key, pdf_bytes, content_type="application/pdf")

    # Send email
    email_sent = False
    email_error = None

    if settings.SMTP_HOST:
        try:
            msg = MIMEMultipart()
            msg["From"] = settings.SMTP_USER or "safetalk@sqb.uz"
            msg["To"] = settings.CB_EMAIL
            msg["Subject"] = f"SafeTalk DRP — Xavfsizlik intsidenti hisoboti — {threat.detected_url or str(threat.id)[:8]}"

            body = (
                f"Hurmatli Kiberxavfsizlik bo'limi,\n\n"
                f"SafeTalk DRP tizimi tomonidan yangi xavfsizlik intsidenti aniqlandi.\n\n"
                f"Tahdid ID: {threat.id}\n"
                f"URL: {threat.detected_url or '—'}\n"
                f"Risk ball: {threat.risk_score}/100\n\n"
                f"Batafsil ma'lumot ilova qilingan PDF hisobotda keltirilgan.\n\n"
                f"Hurmat bilan,\n"
                f"{requested_by_name}\n"
                f"SafeTalk DRP · SQB Bank"
            )
            msg.attach(MIMEText(body, "plain", "utf-8"))

            attachment = MIMEBase("application", "pdf")
            attachment.set_payload(pdf_bytes)
            encoders.encode_base64(attachment)
            attachment.add_header(
                "Content-Disposition",
                f'attachment; filename="SafeTalk_Incident_{str(threat.id)[:8]}.pdf"',
            )
            msg.attach(attachment)

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)

            email_sent = True
            logger.info(f"Sent incident report email to {settings.CB_EMAIL}")
        except Exception as e:
            email_error = str(e)
            logger.error(f"Failed to send email: {e}")
    else:
        email_error = "SMTP not configured"

    return {
        "report_key": report_key,
        "pdf_size": len(pdf_bytes),
        "email_sent": email_sent,
        "email_error": email_error,
        "recipient": settings.CB_EMAIL,
    }
