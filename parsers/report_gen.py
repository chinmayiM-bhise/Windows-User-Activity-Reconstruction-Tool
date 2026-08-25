# parsers/report_gen.py
r"""
AegisDFIR Enterprise PDF Audit Report Generator.
Builds publication-ready executive forensic audit reports with:
- SHA-256 evidence integrity hashing
- Case metadata & Examiner details
- Chronological activity density & artifact distribution charts
- Reconstructed session timelines with MITRE ATT&CK mapping
- Chunk-safe Platypus tables (prevents LayoutError on large datasets)
"""

import os
import html
import sqlite3
import hashlib
import datetime
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
    KeepTogether
)
from reportlab.lib.units import mm

PAGE_MARGIN_MM = 16
CHUNK_SIZE = 45  # Rows per chunk to guarantee clean page splits in ReportLab
DEFAULT_FONT = "Helvetica"

def _sha256_file(path: str) -> str:
    if not os.path.isfile(path):
        return "N/A"
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"

def _safe_isoformat(ts: Optional[str]) -> str:
    if not ts:
        return ""
    try:
        s = str(ts).strip()
        if s.endswith("Z"):
            s = s[:-1]
        dt = datetime.datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)[:19]

def _coalesce_time(row: Dict[str, Any]) -> str:
    return str(row.get("timestamp") or row.get("last_access") or "")

def _parse_time_for_sort(s: str) -> datetime.datetime:
    if not s:
        return datetime.datetime.min
    try:
        clean = s.replace("Z", "").strip()
        return datetime.datetime.fromisoformat(clean)
    except Exception:
        try:
            return datetime.datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.datetime.min

def _get_styles():
    ss = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("TitleStyle", parent=ss["Title"], fontName=f"{DEFAULT_FONT}-Bold", fontSize=18, leading=22, textColor=colors.HexColor("#0F172A")),
        "h1": ParagraphStyle("H1Style", parent=ss["Heading1"], fontName=f"{DEFAULT_FONT}-Bold", fontSize=13, leading=16, textColor=colors.HexColor("#0284C7"), spaceBefore=10, spaceAfter=4),
        "h2": ParagraphStyle("H2Style", parent=ss["Heading2"], fontName=f"{DEFAULT_FONT}-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#1E293B"), spaceBefore=8, spaceAfter=4),
        "h3": ParagraphStyle("H3Style", parent=ss["Heading3"], fontName=f"{DEFAULT_FONT}-Bold", fontSize=9, leading=12, textColor=colors.HexColor("#334155")),
        "normal": ParagraphStyle("NormalStyle", parent=ss["Normal"], fontName=DEFAULT_FONT, fontSize=8, leading=10, textColor=colors.HexColor("#0F172A")),
        "small": ParagraphStyle("SmallStyle", parent=ss["Normal"], fontName=DEFAULT_FONT, fontSize=7, leading=9, textColor=colors.HexColor("#475569")),
        "mono": ParagraphStyle("MonoStyle", parent=ss["Normal"], fontName="Courier", fontSize=7, leading=9, textColor=colors.HexColor("#0284C7")),
        "threat": ParagraphStyle("ThreatStyle", parent=ss["Normal"], fontName=f"{DEFAULT_FONT}-Bold", fontSize=7, leading=9, textColor=colors.HexColor("#DC2626")),
        "mitre": ParagraphStyle("MitreStyle", parent=ss["Normal"], fontName="Courier-Bold", fontSize=7, leading=9, textColor=colors.HexColor("#7C3AED")),
        "italic": ParagraphStyle("ItalicStyle", parent=ss["Italic"], fontName=f"{DEFAULT_FONT}-Oblique", fontSize=7, leading=9, textColor=colors.HexColor("#64748B")),
    }
    return styles

def _content_width(doc) -> float:
    return doc.width

def _hex_of_type(atype: str) -> str:
    t = (atype or "").lower()
    if "prefetch" in t: return "#16A34A"
    if "browser" in t: return "#0284C7"
    if "powershell" in t: return "#EA580C"
    if "usb" in t: return "#9333EA"
    if "recycle" in t: return "#DC2626"
    if "event" in t or "logon" in t: return "#D97706"
    if "shellbag" in t: return "#0891B2"
    if "userassist" in t: return "#0D9488"
    if "bam" in t: return "#DB2777"
    if "startup" in t: return "#B45309"
    return "#475569"

def _embed_image_if_exists(story, path_or_stream, doc, caption=None):
    if not path_or_stream:
        return
    try:
        max_w = _content_width(doc)
        if isinstance(path_or_stream, str) and os.path.exists(path_or_stream):
            img = Image(path_or_stream, width=max_w, height=max_w * 0.38)
            img.hAlign = "CENTER"
            story.append(img)
            if caption:
                story.append(Paragraph(caption, _get_styles()["italic"]))
            story.append(Spacer(1, 8))
    except Exception:
        pass

def _p(text: Any, style, allow_markup: bool = False) -> Paragraph:
    if text is None:
        text = ""
    s = str(text)
    if not allow_markup:
        s = html.escape(s)
    return Paragraph(s, style)

def fetch_artifacts(db_path: str) -> List[Dict[str, Any]]:
    if not os.path.isfile(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, artifact_type, name, path, timestamp, last_access, extra, details FROM artifacts ORDER BY id ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def generate_pdf_report(db_path: str, output_path: str, title: str = "AegisDFIR Forensic Audit Report", metadata: Optional[Dict[str, str]] = None) -> str:
    rows = fetch_artifacts(db_path)
    total = len(rows)
    by_type = Counter([r.get("artifact_type") or "unknown" for r in rows])
    rows_sorted = sorted(rows, key=lambda r: _parse_time_for_sort(_coalesce_time(r)), reverse=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=PAGE_MARGIN_MM * mm,
        leftMargin=PAGE_MARGIN_MM * mm,
        topMargin=PAGE_MARGIN_MM * mm,
        bottomMargin=PAGE_MARGIN_MM * mm,
    )
    styles = _get_styles()
    story = []

    # Title & Header Banner
    story.append(Paragraph("🛡️ AEGIS-DFIR | Forensic Audit Report", styles["title"]))
    story.append(Spacer(1, 4))
    gen_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"<b>Report Generated:</b> {gen_time} &nbsp;|&nbsp; <b>Tool Version:</b> v1.3.1", styles["small"]))
    story.append(Spacer(1, 8))

    if metadata is None:
        metadata = {}

    metadata["DB SHA256"] = _sha256_file(db_path)
    metadata["Total Artifacts"] = f"{total:,}"

    # Metadata Table
    meta_order = ["Case ID", "Evidence ID", "Examiner", "Description", "DB SHA256", "Total Artifacts", "Notes"]
    meta_lines = []
    for key in meta_order:
        val = metadata.get(key, "")
        if val:
            meta_lines.append([Paragraph(f"<b>{html.escape(key)}</b>", styles["small"]), _p(str(val), styles["small"])])

    types_summary = ", ".join(f"{html.escape(str(k))} ({v})" for k, v in by_type.most_common(8))
    meta_lines.append([Paragraph("<b>Artifact Summary</b>", styles["small"]), _p(types_summary, styles["small"])])

    meta_tbl = Table(meta_lines, colWidths=[38 * mm, _content_width(doc) - 38 * mm])
    meta_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 10))

    # Embed Charts
    chart_counts = metadata.get("chart_counts")
    chart_timeline = metadata.get("chart_timeline")
    if chart_timeline:
        _embed_image_if_exists(story, chart_timeline, doc, caption="Chronological Activity Density Histogram")
    if chart_counts:
        _embed_image_if_exists(story, chart_counts, doc, caption="Evidence Distribution by Forensic Category")

    # Chronological Evidence Table (Chunk-safe)
    story.append(Paragraph("Forensic Activity Timeline (Chronological Audit)", styles["h1"]))
    header = ["Time (UTC)", "Artifact Type", "Binary / Resource", "Source Path", "Threat / Extra"]
    total_w = _content_width(doc)
    col_widths = [total_w * 0.17, total_w * 0.14, total_w * 0.22, total_w * 0.30, total_w * 0.17]

    sample_rows = rows_sorted[:250]  # Safe top 250 records for executive report
    chunks = [sample_rows[i:i + CHUNK_SIZE] for i in range(0, len(sample_rows), CHUNK_SIZE)]

    for chunk_idx, chunk in enumerate(chunks):
        tbl_data = [[_p(h, styles["h3"]) for h in header]]
        for r in chunk:
            time_text = _safe_isoformat(_coalesce_time(r))
            a_type = r.get("artifact_type") or "unknown"
            a_label = f'<font color="{_hex_of_type(a_type)}"><b>{html.escape(str(a_type))}</b></font>'
            
            extra_str = r.get("extra") or ""
            is_threat = "threat_tag" in extra_str.lower() or "critical" in extra_str.lower() or "tampering" in extra_str.lower()
            extra_style = styles["threat"] if is_threat else styles["small"]

            tbl_data.append([
                _p(time_text, styles["mono"]),
                _p(a_label, styles["normal"], allow_markup=True),
                _p(r.get("name") or "", styles["normal"]),
                _p(r.get("path") or "", styles["small"]),
                _p(extra_str[:50], extra_style),
            ])

        chunk_tbl = Table(tbl_data, colWidths=col_widths, repeatRows=1)
        chunk_tbl.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        for i in range(1, len(tbl_data)):
            if i % 2 == 0:
                chunk_tbl.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC"))]))
        
        story.append(chunk_tbl)
        story.append(Spacer(1, 6))

    if len(rows_sorted) > 250:
        story.append(Paragraph(f"<i>... Displaying top 250 of {len(rows_sorted):,} indexed artifacts. Complete raw dataset is exported via CSV/JSON.</i>", styles["italic"]))

    doc.build(story)
    return output_path

def generate_correlation_pdf(db_path: str, output_path: str, title: str = "AegisDFIR Reconstructed Activity & Timeline Report", metadata: Optional[Dict[str, str]] = None) -> str:
    try:
        from correlator import correlate_artifacts
    except Exception as exc:
        raise RuntimeError(f"Could not import correlator: {exc}")

    conn = sqlite3.connect(db_path)
    try:
        rows = correlate_artifacts(conn)
    finally:
        conn.close()

    sessions = defaultdict(list)
    for r in rows:
        sess = r.get("session", 1)
        sessions[sess].append(r)

    total_sessions = len(sessions)
    total_events = len(rows)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=PAGE_MARGIN_MM * mm,
        leftMargin=PAGE_MARGIN_MM * mm,
        topMargin=PAGE_MARGIN_MM * mm,
        bottomMargin=PAGE_MARGIN_MM * mm,
    )
    styles = _get_styles()
    story = []

    # Title & Metadata
    story.append(Paragraph("⏱️ AEGIS-DFIR | Correlation & Activity Reconstruction Report", styles["title"]))
    story.append(Spacer(1, 4))
    gen_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"<b>Report Generated:</b> {gen_time} &nbsp;|&nbsp; <b>Total Reconstructed Sessions:</b> {total_sessions} &nbsp;|&nbsp; <b>Total Correlated Events:</b> {total_events}", styles["small"]))
    story.append(Spacer(1, 8))

    if metadata is None:
        metadata = {}

    metadata["DB SHA256"] = _sha256_file(db_path)
    metadata["Total Sessions"] = str(total_sessions)
    metadata["Total Correlated Events"] = str(total_events)

    meta_lines = []
    for key in ["Case ID", "Evidence ID", "Examiner", "Description", "DB SHA256", "Total Sessions", "Notes"]:
        val = metadata.get(key, "")
        if val:
            meta_lines.append([Paragraph(f"<b>{html.escape(key)}</b>", styles["small"]), _p(str(val), styles["small"])])

    meta_tbl = Table(meta_lines, colWidths=[38 * mm, _content_width(doc) - 38 * mm])
    meta_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 10))

    # Embed Charts
    chart_timeline = metadata.get("chart_timeline")
    if chart_timeline:
        _embed_image_if_exists(story, chart_timeline, doc, caption="Correlated Activity Timeline Distribution")

    # Sessions Breakdown
    story.append(Paragraph("Reconstructed Chronological Sessions & MITRE ATT&CK Tags", styles["h1"]))
    total_w = _content_width(doc)
    col_w = [total_w * 0.16, total_w * 0.12, total_w * 0.44, total_w * 0.16, total_w * 0.12]

    for sess_id, items in sorted(sessions.items()):
        story.append(Paragraph(f"<b>Session {sess_id}</b> ({len(items)} events)", styles["h2"]))
        
        data = [[_p("Time (UTC)", styles["h3"]), _p("Type", styles["h3"]), _p("Reconstructed Action", styles["h3"]), _p("Threat Indicator", styles["h3"]), _p("MITRE Tag", styles["h3"])]]
        
        for it in items[:60]:
            t = _safe_isoformat(it.get("timestamp") or it.get("last_access") or "")
            atype = it.get("artifact_type") or ""
            detail = str(it.get("detail") or "")
            if len(detail) > 240:
                detail = detail[:237] + "..."
            anomaly = str(it.get("anomaly") or "")
            if len(anomaly) > 120:
                anomaly = anomaly[:117] + "..."
            mitre = str(it.get("mitre") or "")

            data.append([
                _p(t, styles["mono"]),
                _p(f'<font color="{_hex_of_type(atype)}"><b>{html.escape(atype)}</b></font>', styles["normal"], allow_markup=True),
                _p(detail, styles["normal"]),
                _p(anomaly, styles["threat"] if anomaly else styles["small"]),
                _p(mitre, styles["mitre"] if mitre else styles["small"])
            ])

        t_tbl = Table(data, colWidths=col_w, repeatRows=1)
        t_tbl.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDE9FE")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        for i in range(1, len(data)):
            if i % 2 == 0:
                t_tbl.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC"))]))
        
        story.append(t_tbl)
        story.append(Spacer(1, 8))

    doc.build(story)
    return output_path
