"""
reposcan/scorer.py — Three-Analyst Council Scorer for RepoScan.

Formula:
- Inside each analyst: `score_i = 1 − Π(1 − severity × confidence)`
- Overall weighted average: `raw_pct = 100 × (Σ w_i · score_i / Σ w_i)`
  with weights `(cicd=1.5, supply_chain=1.0, ai_surface=1.5)` (total weight = 4.0).
- Critical floor: if any finding has `severity == "critical"`, `proneness_pct = max(raw_pct, 70.0)`.
- Risk bands: Low < 30, Moderate 30–59, High 60–79, Critical ≥ 80.
"""
from __future__ import annotations

from typing import Dict, List, Literal, Tuple
from analysts.base import compute_analyst_score
from models import (
    ANALYST_LABELS,
    ANALYST_WEIGHTS,
    AnalystBreakdown,
    Finding,
    OWASP_ASI_CATALOG,
)


def classify_risk_band(score_pct: float) -> Literal["Low", "Moderate", "High", "Critical"]:
    if score_pct >= 80.0:
        return "Critical"
    if score_pct >= 60.0:
        return "High"
    if score_pct >= 30.0:
        return "Moderate"
    return "Low"


def build_asi_heatmap(findings: List[Finding]) -> Dict[str, int]:
    counts = {asi: 0 for asi in OWASP_ASI_CATALOG.keys()}
    for f in findings:
        for asi in f.asi_ids:
            if asi in counts:
                counts[asi] += 1
    return counts


def score_findings(
    findings: List[Finding],
) -> Tuple[float, float, bool, Literal["Low", "Moderate", "High", "Critical"], str, List[AnalystBreakdown]]:
    """
    Pure deterministic function that computes:
    `(proneness_pct, raw_weighted_pct, critical_floor_applied, risk_band, arithmetic_str, analyst_breakdowns)`
    from any list of `Finding` objects.
    """
    by_analyst: Dict[str, List[Finding]] = {
        "cicd": [],
        "supply_chain": [],
        "ai_surface": [],
    }
    for f in findings:
        by_analyst.setdefault(f.analyst, []).append(f)

    analysts_out: List[AnalystBreakdown] = []
    for key in ("cicd", "supply_chain", "ai_surface"):
        f_list = by_analyst.get(key, [])
        sc, form = compute_analyst_score(f_list)
        analysts_out.append(
            AnalystBreakdown(
                analyst=key,  # type: ignore[arg-type]
                name=ANALYST_LABELS[key],
                weight=ANALYST_WEIGHTS[key],
                score=sc,
                findings_count=len(f_list),
                formula_detail=form,
            )
        )

    s_cicd = analysts_out[0].score
    s_sc = analysts_out[1].score
    s_ai = analysts_out[2].score

    w_cicd = ANALYST_WEIGHTS["cicd"]
    w_sc = ANALYST_WEIGHTS["supply_chain"]
    w_ai = ANALYST_WEIGHTS["ai_surface"]
    total_w = w_cicd + w_sc + w_ai  # 4.0

    weighted_ratio = (s_cicd * w_cicd + s_sc * w_sc + s_ai * w_ai) / total_w
    raw_pct = round(weighted_ratio * 100.0, 1)

    has_critical = any(f.severity == "critical" for f in findings)
    critical_floor_applied = has_critical and raw_pct < 70.0
    final_pct = max(raw_pct, 70.0) if has_critical else raw_pct
    final_pct = round(min(100.0, max(0.0, final_pct)), 1)

    arith = (
        f"({s_cicd:.2f}×{w_cicd:.1f} + {s_sc:.2f}×{w_sc:.1f} + {s_ai:.2f}×{w_ai:.1f}) "
        f"/ {total_w:.1f} = {weighted_ratio:.2f} → {raw_pct:.1f}%"
    )
    if critical_floor_applied:
        arith += f" [critical floor → {final_pct:.1f}%]"

    band = classify_risk_band(final_pct)
    return final_pct, raw_pct, critical_floor_applied, band, arith, analysts_out
