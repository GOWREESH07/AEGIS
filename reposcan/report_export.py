"""
reposcan/report_export.py — Export RepoScanReport as Markdown (`report.md`) and PDF (`report.pdf`).
Uses pure-Python minimal PDF generation so it works with zero external system binary dependencies.
"""
from __future__ import annotations

from typing import List
from models import OWASP_ASI_CATALOG, RepoScanReport


def render_markdown_report(report: RepoScanReport) -> str:
    lines: List[str] = [
        f"# AEGIS RepoScan Security Report — `{report.repo_owner}/{report.repo_name}`",
        "",
        f"- **Scan ID:** `{report.scan_id}`",
        f"- **Repository URL:** {report.url}",
        f"- **Commit SHA:** `{report.commit_sha}`",
        f"- **Scanned At:** `{report.scanned_at}`",
        f"- **AI-Attack Proneness Score:** **{report.proneness_pct:.1f}% ({report.risk_band} Risk)**",
        f"- **Score Arithmetic:** `{report.score_arithmetic}`",
        f"- **Coverage:** {report.coverage_pct:.1f}% ({report.files_analysed}/{report.files_eligible} eligible files)",
        "",
        "## Executive Summary",
        "",
        report.summary_text,
        "",
    ]
    if report.llm_summary_text:
        lines.extend(["### AI-Written Summary", "", report.llm_summary_text, ""])

    lines.extend(
        [
            "## Three-Analyst Council Breakdown",
            "",
            "| Analyst | Weight | Score (0–1) | Findings | Formula |",
            "|---|---:|---:|---:|---|",
        ]
    )
    for a in report.analysts:
        lines.append(
            f"| {a.name} | ×{a.weight:.1f} | {a.score:.2f} | {a.findings_count} | `{a.formula_detail}` |"
        )

    lines.extend(["", "## OWASP Top 10 for Agentic Applications (2026) Heatmap", "", "| ASI ID | Category | Findings |", "|---|---|---:|"])
    for asi_id, desc in OWASP_ASI_CATALOG.items():
        cnt = report.asi_heatmap.get(asi_id, 0)
        lines.append(f"| `{asi_id}` | {desc} | {cnt} |")

    lines.extend(["", "## Detailed Findings", ""])
    if not report.findings:
        lines.append("No findings detected.")
    else:
        for idx, f in enumerate(report.findings, start=1):
            inc = f" — *Resembles: {f.incident_ref}*" if f.incident_ref else ""
            lines.extend(
                [
                    f"### {idx}. [{f.check_id}] {f.title} (`{f.severity.upper()}`, weight={f.severity_weight})",
                    f"- **Location:** `{f.file}:{f.line}`",
                    f"- **OWASP ASI:** `{', '.join(f.asi_ids)}`{inc}",
                    f"- **Evidence:** `{f.evidence}`",
                    f"- **Why it matters:** {f.why_it_matters}",
                    "",
                ]
            )

    lines.extend(
        [
            "## Prioritised Improvements",
            "",
            f"- **Projected Score After All High-Impact Fixes:** **{report.projected_score_all_high_impact_pct:.1f}%**",
            "",
        ]
    )
    for idx, imp in enumerate(report.improvements, start=1):
        lines.extend(
            [
                f"### Fix {idx}: [{imp.finding_check_id}] `{imp.file}:{imp.line}` → Projected Score: **{imp.projected_score_pct:.1f}%** (−{imp.score_reduction_pct:.1f}%)",
                f"{imp.description}",
                "",
                "```",
                imp.snippet,
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def _pdf_escape(text: str) -> str:
    clean = "".join(c if 32 <= ord(c) <= 126 else " " for c in text)
    return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf_bytes(title: str, markdown_text: str) -> bytes:
    """
    Generate a clean, standards-compliant multi-line PDF document in pure Python.
    """
    raw_lines = [title, "=" * len(title), ""]
    for ln in markdown_text.splitlines():
        cleaned = ln.replace("**", "").replace("`", "")
        while len(cleaned) > 95:
            raw_lines.append(cleaned[:95])
            cleaned = "  " + cleaned[95:]
        raw_lines.append(cleaned)

    # Paginate at 48 lines per page
    lines_per_page = 48
    pages: List[List[str]] = [
        raw_lines[i : i + lines_per_page] for i in range(0, max(1, len(raw_lines)), lines_per_page)
    ]

    objects: List[bytes] = []
    # Obj 1: Catalog, Obj 2: Pages, Obj 3: Font
    page_obj_ids = []
    content_obj_ids = []
    next_id = 4
    for _ in pages:
        page_obj_ids.append(next_id)
        content_obj_ids.append(next_id + 1)
        next_id += 2

    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects.append(
        f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {len(pages)} >>\nendobj\n".encode("latin-1")
    )
    objects.append(
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
    )

    for page_lines, pid, cid in zip(pages, page_obj_ids, content_obj_ids):
        stream_cmds = ["BT", "/F1 9 Tf", "36 756 Td", "14 TL"]
        for line in page_lines:
            stream_cmds.append(f"({_pdf_escape(line)}) Tj T*")
        stream_cmds.append("ET")
        stream_bytes = "\n".join(stream_cmds).encode("latin-1")

        page_obj = (
            f"{pid} 0 obj\n"
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >>\n"
            f"endobj\n"
        ).encode("latin-1")
        content_obj = (
            f"{cid} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )
        objects.append(page_obj)
        objects.append(content_obj)

    header = b"%PDF-1.4\n"
    body = b""
    offsets = [0]
    curr_offset = len(header)
    for obj in objects:
        offsets.append(curr_offset)
        body += obj
        curr_offset += len(obj)

    xref_lines = [f"xref\n0 {len(objects) + 1}", "0000000000 65535 f "]
    for off in offsets[1:]:
        xref_lines.append(f"{off:010d} 00000 n ")
    xref_bytes = ("\n".join(xref_lines) + "\n").encode("latin-1")
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{curr_offset}\n%%EOF\n"
    ).encode("latin-1")
    return header + body + xref_bytes + trailer
