"""
reposcan/checks/base.py — Base plug-in class for all RepoScan checks.
"""
from __future__ import annotations

from typing import List, Optional
from cloner import RepoContext
from models import AnalystType, Finding, SEVERITY_WEIGHTS, SeverityType


class RepoCheck:
    id: str = "BASE"
    analyst: AnalystType = "cicd"
    title: str = "Base Check"
    severity: SeverityType = "medium"
    asi_ids: List[str] = []
    incident_ref: Optional[str] = None

    def make_finding(
        self,
        file: str,
        line: int,
        evidence: str,
        why_it_matters: str,
        confidence: float = 1.0,
        severity_override: Optional[SeverityType] = None,
        title_override: Optional[str] = None,
    ) -> Finding:
        sev = severity_override or self.severity
        return Finding(
            check_id=self.id,
            analyst=self.analyst,
            title=title_override or self.title,
            severity=sev,
            severity_weight=SEVERITY_WEIGHTS[sev],
            confidence=confidence,
            file=file,
            line=max(1, line),
            evidence=evidence[:240],
            why_it_matters=why_it_matters,
            asi_ids=list(self.asi_ids),
            incident_ref=self.incident_ref,
        )

    def run(self, repo_ctx: RepoContext) -> List[Finding]:
        raise NotImplementedError


def find_line_number(text: str, needle: str) -> int:
    if not needle:
        return 1
    for idx, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return idx
    return 1
