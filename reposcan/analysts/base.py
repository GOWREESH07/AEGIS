"""
reposcan/analysts/base.py — Base Analyst scorer implementing:
`score = 1 − Π(1 − severity × confidence)` over triggered checks.
"""
from __future__ import annotations

from typing import List
from checks.base import RepoCheck
from cloner import RepoContext
from models import ANALYST_LABELS, ANALYST_WEIGHTS, AnalystBreakdown, AnalystType, Finding, SEVERITY_WEIGHTS


def compute_analyst_score(findings: List[Finding]) -> tuple[float, str]:
    """
    Compute `1 − Π(1 − severity × confidence)` over *findings*.
    Returns `(score, formula_string)`.
    """
    if not findings:
        return 0.0, "1 - 1.000 = 0.00"

    product = 1.0
    terms = []
    for f in findings:
        sev_w = SEVERITY_WEIGHTS.get(f.severity, f.severity_weight)
        term = max(0.0, min(1.0, sev_w * f.confidence))
        product *= (1.0 - term)
        terms.append(f"(1 - {sev_w:.2f}×{f.confidence:.2f})")

    score = max(0.0, min(1.0, 1.0 - product))
    joined_terms = " × ".join(terms[:4])
    if len(terms) > 4:
        joined_terms += f" × ... ({len(terms)} findings)"
    formula = f"1 - [{joined_terms}] = {score:.2f}"
    return round(score, 4), formula


class BaseRepoAnalyst:
    analyst_key: AnalystType = "cicd"
    checks: List[RepoCheck] = []

    def evaluate(self, repo_ctx: RepoContext) -> tuple[AnalystBreakdown, List[Finding]]:
        findings: List[Finding] = []
        for chk in self.checks:
            findings.extend(chk.run(repo_ctx))

        score, formula = compute_analyst_score(findings)
        breakdown = AnalystBreakdown(
            analyst=self.analyst_key,
            name=ANALYST_LABELS[self.analyst_key],
            weight=ANALYST_WEIGHTS[self.analyst_key],
            score=score,
            findings_count=len(findings),
            formula_detail=formula,
        )
        return breakdown, findings
