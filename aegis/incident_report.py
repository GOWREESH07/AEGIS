"""
aegis/incident_report.py — Incident Report Export (Markdown & PDF) for any attack run (Feature 5.4).
Includes timeline, Council scores, MITRE ATLAS + OWASP ASI tags, actions taken, and signatures learned.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from guardrail import get_stage_tags


STAGE_LABELS = {
    1: "01 RECON",
    2: "02 ADAPT",
    3: "03 AILM",
    4: "04 LATERAL",
    5: "05 EXEC",
    6: "06 MCP_POISON",
    7: "07 RAG_INJECT",
    8: "08 SLOPSQUAT",
    9: "09 CRED_HARVEST",
}


def generate_incident_markdown(
    run_id: str,
    events: List[Dict[str, Any]],
    signatures: List[Dict[str, Any]],
    blocklist: List[Dict[str, Any]],
) -> str:
    now_iso = datetime.now(timezone.utc).isoformat()
    lines = [
        f"# AEGIS Autonomous Defense Incident Report — `{run_id}`",
        "",
        f"- **Generated At:** `{now_iso}`",
        f"- **Total Defense Events Recorded:** {len(events)}",
        f"- **Active Quarantined Hosts:** {len(blocklist)}",
        f"- **Self-Healing Signatures Learned:** {len(signatures)}",
        "",
        "## 1. Attack Timeline & Council Verdicts",
        "",
        "| Timestamp | Stage | Source IP | Event | Action | Weighted Conf | Latency (ms) | MITRE ATLAS | OWASP ASI |",
        "|---|---|---|---|---|---:|---:|---|---|",
    ]
    for ev in events[-40:]:
        st = ev.get("stage") or 1
        atlas, asi = get_stage_tags(st)
        verdict = ev.get("verdict") or {}
        conf = verdict.get("weighted_confidence", 0.0)
        lat = verdict.get("verdict_ms", 0.0)
        act = verdict.get("action", ev.get("event_type", "allow"))
        ts_val = ev.get("ts", 0.0)
        ts_str = datetime.fromtimestamp(ts_val, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3] if ts_val else now_iso
        lines.append(
            f"| `{ts_str}` | {STAGE_LABELS.get(st, f'S{st}')} | `{ev.get('source_ip', 'unknown')}` | "
            f"`{ev.get('event_type', 'detect')}` | **{str(act).upper()}** | {conf:.3f} | {lat:.2f} | `{atlas}` | `{asi}` |"
        )

    lines.extend(
        [
            "",
            "## 2. Per-Analyst Consensus Breakdown (Latest Verdict)",
            "",
        ]
    )
    if events and events[-1].get("verdict"):
        v = events[-1]["verdict"]
        for sc in v.get("scores", []):
            lines.append(
                f"- **{sc.get('analyst_name')}**: confidence=`{sc.get('confidence', 0.0):.3f}` — `{sc.get('reasoning', '')}`"
            )
    else:
        lines.append("- No analyst scores recorded in current window.")

    lines.extend(
        [
            "",
            "## 3. Autonomous Response Actions Taken",
            "",
        ]
    )
    if blocklist:
        for b in blocklist:
            lines.append(
                f"- **Quarantined IP `{b.get('ip')}`** (Stage `0{b.get('stage', 1)}`, Action: `{b.get('action')}`, Confidence: `{b.get('confidence', 0.9):.2f}`)"
            )
    else:
        lines.append("- All hostile sessions terminated; no currently active TTL blocks remaining.")

    lines.extend(
        [
            "",
            "## 4. Self-Healing Signatures Learned",
            "",
            "| Signature ID | Stage | First Detected (ms) | Second Detected (ms) | Feature Hash |",
            "|---|---:|---:|---:|---|",
        ]
    )
    for sig in signatures[:15]:
        sec = f"{sig['second_detected_ms']:.1f}" if sig.get("second_detected_ms") is not None else "—"
        lines.append(
            f"| `{sig.get('id')}` | {STAGE_LABELS.get(sig.get('stage', 1), 'S1')} | "
            f"{float(sig.get('first_detected_ms') or 0.0):.1f} | {sec} | `{str(sig.get('feature_hash', ''))[:16]}...` |"
        )

    return "\n".join(lines)


def _pdf_escape(text: str) -> str:
    clean = "".join(c if 32 <= ord(c) <= 126 else " " for c in text)
    return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_incident_pdf(title: str, markdown_text: str) -> bytes:
    raw_lines = [title, "=" * len(title), ""]
    for ln in markdown_text.splitlines():
        cleaned = ln.replace("**", "").replace("`", "")
        while len(cleaned) > 95:
            raw_lines.append(cleaned[:95])
            cleaned = "  " + cleaned[95:]
        raw_lines.append(cleaned)

    lines_per_page = 48
    pages = [raw_lines[i : i + lines_per_page] for i in range(0, max(1, len(raw_lines)), lines_per_page)]
    objects: List[bytes] = []
    page_ids = []
    content_ids = []
    nid = 4
    for _ in pages:
        page_ids.append(nid)
        content_ids.append(nid + 1)
        nid += 2

    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects.append(f"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>\nendobj\n".encode("latin-1"))
    objects.append(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

    for plines, pid, cid in zip(pages, page_ids, content_ids):
        cmds = ["BT", "/F1 9 Tf", "36 756 Td", "14 TL"]
        for l in plines:
            cmds.append(f"({_pdf_escape(l)}) Tj T*")
        cmds.append("ET")
        sbytes = "\n".join(cmds).encode("latin-1")
        pobj = (
            f"{pid} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >>\nendobj\n"
        ).encode("latin-1")
        cobj = f"{cid} 0 obj\n<< /Length {len(sbytes)} >>\nstream\n".encode("latin-1") + sbytes + b"\nendstream\nendobj\n"
        objects.append(pobj)
        objects.append(cobj)

    header = b"%PDF-1.4\n"
    body = b""
    offsets = [0]
    curr = len(header)
    for o in objects:
        offsets.append(curr)
        body += o
        curr += len(o)
    xref = [f"xref\n0 {len(objects) + 1}", "0000000000 65535 f "]
    for off in offsets[1:]:
        xref.append(f"{off:010d} 00000 n ")
    xref_b = ("\n".join(xref) + "\n").encode("latin-1")
    trailer = f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{curr}\n%%EOF\n".encode("latin-1")
    return header + body + xref_b + trailer
