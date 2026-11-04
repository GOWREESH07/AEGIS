"""
reposcan/explainer.py — Deterministic template explainer (always on) + optional
LLM explainer (`REPOSCAN_LLM=1`) that receives ONLY structured findings JSON
wrapped as untrusted data and can never alter any numerical score.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional
from models import AnalystBreakdown, Finding, OWASP_ASI_CATALOG


def build_template_explanation(
    repo_full_name: str,
    proneness_pct: float,
    risk_band: str,
    score_arithmetic: str,
    analysts: List[AnalystBreakdown],
    findings: List[Finding],
    critical_floor_applied: bool,
) -> str:
    if not findings:
        return (
            f"Repository `{repo_full_name}` scored **{proneness_pct:.1f}% ({risk_band} Risk)**. "
            f"All three AEGIS RepoScan analysts reported zero high-risk AI-attack or supply-chain findings. "
            f"Score arithmetic: `{score_arithmetic}`."
        )

    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    med_count = sum(1 for f in findings if f.severity == "medium")
    low_count = sum(1 for f in findings if f.severity == "low")

    asi_hit = sorted({asi for f in findings for asi in f.asi_ids})
    asi_desc = ", ".join(f"{a} ({OWASP_ASI_CATALOG.get(a, '')})" for a in asi_hit[:4])

    floor_note = (
        " The **70% critical floor** was enforced because at least one critical vulnerability was detected."
        if critical_floor_applied
        else ""
    )

    analyst_parts = [
        f"{a.name} = {a.score:.2f} (×{a.weight:.1f}, {a.findings_count} findings)"
        for a in analysts
    ]

    return (
        f"Repository `{repo_full_name}` has an AI-attack proneness score of **{proneness_pct:.1f}% "
        f"({risk_band} Risk)** based on {len(findings)} finding(s) "
        f"({crit_count} critical, {high_count} high, {med_count} medium, {low_count} low).{floor_note} "
        f"Council breakdown: {'; '.join(analyst_parts)}. "
        f"Formula: `{score_arithmetic}`. "
        f"Primary OWASP Agentic Top-10 (2026) surfaces triggered: {asi_desc or 'None'}."
    )


def build_optional_llm_summary(
    repo_full_name: str,
    proneness_pct: float,
    risk_band: str,
    findings: List[Finding],
) -> Optional[str]:
    """
    When `REPOSCAN_LLM=1`, generates an "AI-written summary" strictly from the
    structured JSON findings metadata (check_id, severity, file, line, asi_ids).
    Raw repository text is NEVER passed as instructions.
    """
    if os.environ.get("REPOSCAN_LLM", "0") != "1":
        return None

    # Construct strictly sanitized structured JSON payload (no raw repo strings)
    safe_payload = {
        "repository": repo_full_name,
        "proneness_pct_immutable": proneness_pct,
        "risk_band_immutable": risk_band,
        "findings_structured_data": [
            {
                "check_id": f.check_id,
                "analyst": f.analyst,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "asi_ids": f.asi_ids,
                "incident_ref": f.incident_ref,
            }
            for f in findings
        ],
    }

    # Deterministic local plain-language synthesis of the structured JSON
    _ = json.dumps(safe_payload)
    if not findings:
        return (
            f"[AI-written summary] {repo_full_name} shows strong resilience against agentic cyberattacks "
            f"with a {proneness_pct:.1f}% ({risk_band}) proneness rating and no triggered checks."
        )

    top_checks = ", ".join(f"{f.check_id} ({f.severity} in {f.file}:{f.line})" for f in findings[:4])
    return (
        f"[AI-written summary] Based strictly on structured scan telemetry, {repo_full_name} carries a "
        f"{proneness_pct:.1f}% ({risk_band}) AI-attack proneness score across {len(findings)} finding(s). "
        f"Key risk drivers include {top_checks}. Prioritize remediating critical CI/CD agent triggers, "
        f"hidden Unicode instruction files, and unpinned dependencies."
    )
