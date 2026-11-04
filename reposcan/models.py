"""
reposcan/models.py — Pydantic data models for Repository AI-Attack Proneness Scanner
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


SeverityType = Literal["critical", "high", "medium", "low"]
AnalystType = Literal["cicd", "supply_chain", "ai_surface"]

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 0.45,
    "high": 0.30,
    "medium": 0.15,
    "low": 0.05,
}

ANALYST_WEIGHTS: Dict[str, float] = {
    "cicd": 1.5,
    "supply_chain": 1.0,
    "ai_surface": 1.5,
}

ANALYST_LABELS: Dict[str, str] = {
    "cicd": "CI/CD & Agent-Workflow Analyst",
    "supply_chain": "Supply-Chain Analyst",
    "ai_surface": "AI-Surface Analyst",
}

OWASP_ASI_CATALOG: Dict[str, str] = {
    "ASI01": "Agent Goal Hijacking & Prompt Injection",
    "ASI02": "Excessive Agency & Tool Misuse",
    "ASI03": "Privilege Escalation & Identity Abuse",
    "ASI04": "Agentic Supply-Chain Compromise",
    "ASI05": "Insecure Code Execution & Output Handling",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Multi-Agent Trust & Orchestration Abuse",
    "ASI08": "Cascading Hallucination & Slopsquatting",
    "ASI09": "Insufficient Sandboxing & Human-in-the-Loop",
    "ASI10": "Sensitive Data & Credential Exposure",
}


class Finding(BaseModel):
    check_id: str = Field(..., description="Check identifier (e.g., A1, B2, C1)")
    analyst: AnalystType
    title: str
    severity: SeverityType
    severity_weight: float
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    file: str
    line: int = 1
    evidence: str = Field(..., description="Redacted/masked code or config snippet")
    why_it_matters: str
    asi_ids: List[str] = Field(default_factory=list)
    incident_ref: Optional[str] = None


class AnalystBreakdown(BaseModel):
    analyst: AnalystType
    name: str
    weight: float
    score: float = Field(..., ge=0.0, le=1.0)
    findings_count: int
    formula_detail: str


class ImprovementFix(BaseModel):
    finding_check_id: str
    file: str
    line: int
    title: str
    severity: SeverityType
    description: str
    snippet: str
    projected_score_pct: float
    score_reduction_pct: float


class RepoScanRequest(BaseModel):
    url: str = Field(..., description="Public GitHub URL: https://github.com/<owner>/<repo>")
    ref: Optional[str] = Field(default=None, description="Optional branch, tag, or commit SHA")
    local_path: Optional[str] = Field(default=None, description="Internal fixture path for testing only")


class RepoScanReport(BaseModel):
    scan_id: str
    url: str
    repo_owner: str
    repo_name: str
    commit_sha: str
    scanned_at: str
    proneness_pct: float = Field(..., ge=0.0, le=100.0)
    raw_weighted_pct: float = Field(..., ge=0.0, le=100.0)
    critical_floor_applied: bool = False
    risk_band: Literal["Low", "Moderate", "High", "Critical"]
    score_arithmetic: str
    coverage_pct: float
    files_analysed: int
    files_eligible: int
    analysts: List[AnalystBreakdown]
    asi_heatmap: Dict[str, int]
    findings: List[Finding]
    improvements: List[ImprovementFix]
    projected_score_all_high_impact_pct: float
    summary_text: str
    llm_summary_text: Optional[str] = None
    cached: bool = False
