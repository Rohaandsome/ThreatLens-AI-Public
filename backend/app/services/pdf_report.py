"""Professional PDF threat-intelligence reports from approved share packages.

Every page carries the TLP 2.0 marking in both header and footer. Content
comes exclusively from the analyst-approved package (already filtered and
redacted) — never from the raw analysis.
"""

import io
import re
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..errors import AnalysisError
from ..schemas import SharePrepareResponse
from . import tlp

PAGE_W, PAGE_H = A4

# Header/footer banner styling per TLP designation.
_BANNERS: dict[str, tuple[str, object, object]] = {
    # marking -> (label, background, foreground)
    "TLP:RED": ("TLP:RED", HexColor("#C62828"), white),
    "TLP:AMBER+STRICT": ("TLP:AMBER+STRICT", HexColor("#E65100"), white),
    "TLP:AMBER": ("TLP:AMBER", HexColor("#FFB300"), black),
    "TLP:GREEN": ("TLP:GREEN", HexColor("#2E7D32"), white),
    "TLP:CLEAR": ("TLP:CLEAR", HexColor("#ECEFF1"), black),
}

_SLATE = HexColor("#1F2937")
_GRID = HexColor("#D1D5DB")
_MUTED = HexColor("#6B7280")


def _break_long(text: str, every: int = 32) -> str:
    """Insert zero-width breaks so long tokens (hashes) can wrap in tables."""
    return re.sub(r"(\S{%d})(?=\S)" % every, r"\1​", text)


def _tx(text: str | None) -> str:
    """Escape text for reportlab Paragraph markup."""
    return escape(_break_long(text or ""))


def _fmt_ts(value: datetime | str | None) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "TLTitle", parent=base["Title"], fontSize=22, leading=26,
            textColor=_SLATE, alignment=TA_CENTER, spaceAfter=2 * mm,
        ),
        "subtitle": ParagraphStyle(
            "TLSubtitle", parent=base["Normal"], fontSize=10, leading=13,
            textColor=_MUTED, alignment=TA_CENTER, spaceAfter=6 * mm,
        ),
        "h1": ParagraphStyle(
            "TLH1", parent=base["Heading1"], fontSize=13, leading=16,
            textColor=_SLATE, spaceBefore=6 * mm, spaceAfter=3 * mm,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "TLBody", parent=base["Normal"], fontSize=9, leading=13,
            textColor=black, alignment=TA_LEFT, spaceAfter=2 * mm,
        ),
        "small": ParagraphStyle(
            "TLSmall", parent=base["Normal"], fontSize=8, leading=11,
            textColor=_MUTED, alignment=TA_LEFT, spaceAfter=2 * mm,
        ),
        "quote": ParagraphStyle(
            "TLQuote", parent=base["Normal"], fontSize=8, leading=11,
            textColor=_SLATE, leftIndent=8, spaceAfter=2 * mm,
            borderPadding=(4, 4, 4),
        ),
        "cell": ParagraphStyle(
            "TLCell", parent=base["Normal"], fontSize=8, leading=10.5,
            textColor=black, alignment=TA_LEFT,
        ),
        "cellhead": ParagraphStyle(
            "TLCellHead", parent=base["Normal"], fontSize=8, leading=10.5,
            textColor=white, alignment=TA_LEFT,
        ),
        "cellmono": ParagraphStyle(
            "TLCellMono", parent=base["Normal"], fontName="Courier",
            fontSize=7.5, leading=10, textColor=black, alignment=TA_LEFT,
        ),
    }


def _section_table(
    headers: list[str], rows: list[list[str]], widths: list[float], styles: dict
) -> Table:
    data = [
        [Paragraph(f"<b>{escape(h)}</b>", styles["cellhead"]) for h in headers]
    ]
    for row in rows:
        data.append([Paragraph(cell, styles["cell"]) for cell in row])
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _SLATE),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("GRID", (0, 0), (-1, -1), 0.5, _GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#F3F4F6")]),
            ]
        )
    )
    return table


def _marking_chrome(marking: str, report_ref: str):
    """Header/footer drawer: TLP banner on every page."""
    label, bg, fg = _BANNERS[marking]

    def draw(canvas, doc):  # noqa: ANN001, ANN202 - reportlab callback signature
        canvas.saveState()
        # Header banner (full bleed).
        canvas.setFillColor(bg)
        canvas.rect(0, PAGE_H - 34, PAGE_W, 34, stroke=0, fill=1)
        if marking == "TLP:CLEAR":
            canvas.setStrokeColor(_GRID)
            canvas.line(0, PAGE_H - 34, PAGE_W, PAGE_H - 34)
        canvas.setFillColor(fg)
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawCentredString(PAGE_W / 2, PAGE_H - 23, label)
        # Footer band.
        canvas.setFillColor(bg)
        canvas.rect(0, 0, PAGE_W, 26, stroke=0, fill=1)
        canvas.setFillColor(fg)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(14 * mm, 11, label)
        canvas.setFont("Helvetica", 8)
        canvas.drawCentredString(PAGE_W / 2, 11, f"Page {doc.page}")
        canvas.drawRightString(PAGE_W - 14 * mm, 11, report_ref)
        canvas.restoreState()

    return draw


def build_pdf(package: SharePrepareResponse, analyst: str = "unknown") -> bytes:
    """Render the approved package as a classified PDF report."""
    try:
        marking = tlp.parse_marking(package.classification.proposed)
    except (tlp.InvalidMarkingError, ValueError, AttributeError, TypeError) as exc:
        raise AnalysisError(
            400, "invalid_tlp", "Package carries an invalid TLP marking."
        ) from exc
    content = package.content
    styles = _styles()
    report_ref = f"TL-{package.package_id[:8].upper()}"
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=20 * mm,
        bottomMargin=16 * mm,
        title=f"ThreatLens Intelligence Report {report_ref}",
        author="ThreatLens AI",
        subject=f"{marking} threat intelligence report",
    )
    chrome = _marking_chrome(marking, report_ref)
    story: list = []
    add = story.append
    W = doc.width

    # Title block.
    add(Paragraph("Threat Intelligence Report", styles["title"]))
    add(Paragraph("ThreatLens AI · Critical Infrastructure — Energy Sector", styles["subtitle"]))
    add(Paragraph(f"<b>{escape(marking)}</b>", styles["subtitle"]))
    add(HRFlowable(width="100%", thickness=0.5, color=_GRID))
    add(Spacer(1, 4 * mm))

    # Metadata.
    analyzed = package.analyzed_at
    meta_rows = [
        ["Report ID", f"{report_ref}  (package {package.package_id[:12]}…)"],
        ["Analysis date", _fmt_ts(analyzed)],
        ["Package prepared", _fmt_ts(package.prepared_at)],
        ["Source file", package.source_filename or "unknown"],
        ["AI model", package.model or "unknown"],
        ["Classification", f"{package.classification.effective_source} source → {marking} output"],
        ["Approved by", analyst],
        ["Audit record", package.audit_id[:12] + "…"],
    ]
    meta_data = [
        [Paragraph(f"<b>{escape(k)}</b>", styles["cell"]), Paragraph(_tx(v), styles["cell"])]
        for k, v in meta_rows
    ]
    meta_table = Table(meta_data, colWidths=[W * 0.3, W * 0.7])
    meta_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, _GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    add(meta_table)

    # Handling + disclosure.
    add(Paragraph("Handling", styles["h1"]))
    add(Paragraph(_tx(package.audience), styles["body"]))
    if package.audience_note:
        add(Paragraph(f"<b>Distribution note:</b> {_tx(package.audience_note)}", styles["body"]))
    add(
        Paragraph(
            "<b>AI-assisted analysis disclosure:</b> findings were produced by an AI model "
            f"({escape(package.model or 'unknown')}) from the source report and reviewed by the "
            "approving analyst. Confidence figures are platform assessments, not proof that "
            "an indicator is malicious. Verify independently before acting.",
            styles["small"],
        )
    )
    if package.classification.downgrade:
        add(
            Paragraph(
                "<b>Downgrade notice:</b> this package was explicitly approved for a less "
                "restrictive marking than its source. Confirm recipients are authorized.",
                styles["small"],
            )
        )

    # 1. Executive summary.
    add(Paragraph("1 · Executive Summary", styles["h1"]))
    add(
        Paragraph(
            _tx(content.executive_summary) if content.executive_summary else "<i>Not selected for sharing.</i>",
            styles["body"],
        )
    )

    # 2. Attack techniques.
    add(Paragraph("2 · Attack Techniques (MITRE ATT&CK)", styles["h1"]))
    if content.attack_techniques:
        rows = [
            [
                _tx(t.name),
                _tx(t.mitre_id or "—"),
                "inferred" if t.inferred else "evidence",
                _tx(t.evidence_quote or t.description),
            ]
            for t in content.attack_techniques
        ]
        add(_section_table(["Technique", "ID", "Basis", "Evidence / detail"], rows, [W * 0.24, W * 0.14, W * 0.12, W * 0.5], styles))
    else:
        add(Paragraph("<i>None selected for sharing.</i>", styles["body"]))

    # 3. IOCs.
    add(Paragraph("3 · Indicators of Compromise", styles["h1"]))
    if content.indicators_of_compromise:
        rows = [
            [
                _tx(i.value),
                _tx(i.type),
                "VERIFIED" if i.verified_in_source else "UNVERIFIED — lead only",
                _tx(i.evidence_quote or i.context),
            ]
            for i in content.indicators_of_compromise
        ]
        add(_section_table(["Value", "Type", "Status", "Evidence"], rows, [W * 0.3, W * 0.12, W * 0.2, W * 0.38], styles))
    else:
        add(Paragraph("<i>None selected for sharing.</i>", styles["body"]))

    # 4. CVEs.
    add(Paragraph("4 · Vulnerabilities (CVE)", styles["h1"]))
    if content.cves:
        rows = [
            [_tx(c.id), "VERIFIED" if c.verified_in_source else "UNVERIFIED", _tx(c.description or c.evidence_quote)]
            for c in content.cves
        ]
        add(_section_table(["CVE", "Status", "Detail"], rows, [W * 0.24, W * 0.18, W * 0.58], styles))
    else:
        add(Paragraph("<i>None selected for sharing.</i>", styles["body"]))

    # 5. Affected systems.
    add(Paragraph("5 · Affected Systems", styles["h1"]))
    if content.affected_systems:
        rows = [
            [_tx(s.system), "inferred" if s.inferred else "evidence", _tx(s.detail)]
            for s in content.affected_systems
        ]
        add(_section_table(["System", "Basis", "Detail"], rows, [W * 0.28, W * 0.14, W * 0.58], styles))
    else:
        add(Paragraph("<i>None selected for sharing.</i>", styles["body"]))

    # 6. Recommendations.
    add(Paragraph("6 · Recommendations", styles["h1"]))
    if content.recommendations:
        rows = [[_tx(r.recommendation), _tx(r.priority.upper()), _tx(r.rationale)] for r in content.recommendations]
        add(_section_table(["Recommendation", "Priority", "Rationale"], rows, [W * 0.5, W * 0.14, W * 0.36], styles))
    else:
        add(Paragraph("<i>None selected for sharing.</i>", styles["body"]))

    # 7. Supporting evidence.
    add(Paragraph("7 · Supporting Evidence", styles["h1"]))
    if content.supporting_evidence:
        for e in content.supporting_evidence:
            add(Paragraph(f"“{_tx(e.quote)}”", styles["quote"]))
            add(Paragraph(_tx(e.relevance), styles["small"]))
    else:
        add(Paragraph("<i>None selected for sharing.</i>", styles["body"]))

    # 8. Analyst notes.
    add(Paragraph("8 · Analyst Notes", styles["h1"]))
    add(
        Paragraph(
            _tx(package.analyst_notes).replace("\n", "<br/>") if package.analyst_notes else "<i>No analyst notes recorded.</i>",
            styles["body"],
        )
    )

    # 9. Sharing record.
    add(Paragraph("9 · Sharing Record", styles["h1"]))
    add(
        Paragraph(
            f"Source marking(s): {', '.join(m or 'UNMARKED→classified' for m in package.classification.source_markings)}; "
            f"effective source {escape(package.classification.effective_source)}; shared as {escape(marking)}. "
            f"Redactions applied: {package.redactions_applied}.",
            styles["body"],
        )
    )
    if package.warnings:
        for w in package.warnings:
            add(Paragraph(f"• {_tx(w)}", styles["small"]))
    else:
        add(Paragraph("No warnings.", styles["small"]))

    doc.build(story, onFirstPage=chrome, onLaterPages=chrome)
    return buf.getvalue()
