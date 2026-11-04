"""
reposcan/engine.py — Core static analysis orchestrator for RepoScan.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from analysts.ai_surface_analyst import AISurfaceAnalyst
from analysts.cicd_analyst import CICDAnalyst
from analysts.supply_chain_analyst import SupplyChainAnalyst
from cloner import RepoContext, clone_and_load, load_repo_context, validate_github_url
from explainer import build_optional_llm_summary, build_template_explanation
from improvements import generate_improvements
from models import Finding, RepoScanReport
from registry import RegistryClient
from scorer import build_asi_heatmap, score_findings
from storage import ScanStorage


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class RepoScannerEngine:
    def __init__(
        self,
        db_path: str = "/data/reposcan.db",
        registry_client: Optional[RegistryClient] = None,
    ):
        self.db_path = db_path
        self.storage = ScanStorage(db_path=db_path)
        self.registry = registry_client or RegistryClient(db_path=db_path)
        self.cicd_analyst = CICDAnalyst()
        self.sc_analyst = SupplyChainAnalyst(self.registry)
        self.ai_analyst = AISurfaceAnalyst()

    def scan_context(
        self,
        ctx: RepoContext,
        scan_id: Optional[str] = None,
        progress_cb: Optional[Callable[[str, dict], None]] = None,
    ) -> RepoScanReport:
        sid = scan_id or str(uuid.uuid4())[:12]

        # Check SHA cache first
        cached_report = self.storage.get_by_commit_sha(ctx.url, ctx.commit_sha)
        if cached_report is not None:
            if progress_cb:
                progress_cb("reposcan.done", {"scan_id": cached_report.scan_id, "cached": True, "proneness_pct": cached_report.proneness_pct})
            return cached_report

        if progress_cb:
            progress_cb("reposcan.progress", {"scan_id": sid, "phase": "cicd_analyst", "pct": 25})
        _, cicd_findings = self.cicd_analyst.evaluate(ctx)

        if progress_cb:
            progress_cb("reposcan.progress", {"scan_id": sid, "phase": "supply_chain_analyst", "pct": 55})
        _, sc_findings = self.sc_analyst.evaluate(ctx)

        if progress_cb:
            progress_cb("reposcan.progress", {"scan_id": sid, "phase": "ai_surface_analyst", "pct": 80})
        _, ai_findings = self.ai_analyst.evaluate(ctx)

        all_findings: List[Finding] = cicd_findings + sc_findings + ai_findings
        if progress_cb:
            for f in all_findings:
                progress_cb("reposcan.finding", {"scan_id": sid, "finding": f.model_dump()})

        proneness_pct, raw_pct, floor_applied, risk_band, arith, analysts = score_findings(all_findings)
        asi_heatmap = build_asi_heatmap(all_findings)
        improvements, proj_all_high = generate_improvements(all_findings, proneness_pct)

        repo_full = f"{ctx.owner}/{ctx.repo}"
        summary_text = build_template_explanation(
            repo_full_name=repo_full,
            proneness_pct=proneness_pct,
            risk_band=risk_band,
            score_arithmetic=arith,
            analysts=analysts,
            findings=all_findings,
            critical_floor_applied=floor_applied,
        )
        llm_summary = build_optional_llm_summary(
            repo_full_name=repo_full,
            proneness_pct=proneness_pct,
            risk_band=risk_band,
            findings=all_findings,
        )

        report = RepoScanReport(
            scan_id=sid,
            url=ctx.url,
            repo_owner=ctx.owner,
            repo_name=ctx.repo,
            commit_sha=ctx.commit_sha,
            scanned_at=_utcnow(),
            proneness_pct=proneness_pct,
            raw_weighted_pct=raw_pct,
            critical_floor_applied=floor_applied,
            risk_band=risk_band,
            score_arithmetic=arith,
            coverage_pct=ctx.coverage_pct,
            files_analysed=ctx.files_analysed,
            files_eligible=ctx.files_eligible,
            analysts=analysts,
            asi_heatmap=asi_heatmap,
            findings=all_findings,
            improvements=improvements,
            projected_score_all_high_impact_pct=proj_all_high,
            summary_text=summary_text,
            llm_summary_text=llm_summary,
            cached=False,
        )
        self.storage.save_report(report)
        if progress_cb:
            progress_cb("reposcan.done", {"scan_id": sid, "proneness_pct": proneness_pct, "risk_band": risk_band})
        return report

    def scan_local_directory(
        self,
        path: Path,
        url: str = "https://github.com/fixture/repo",
        scan_id: Optional[str] = None,
        progress_cb: Optional[Callable[[str, dict], None]] = None,
    ) -> RepoScanReport:
        _, owner, repo = validate_github_url(url)
        ctx = load_repo_context(
            root=path,
            url=url,
            owner=owner,
            repo=repo,
            commit_sha="0" * 40,
        )
        return self.scan_context(ctx, scan_id=scan_id, progress_cb=progress_cb)

    def scan_github_url(
        self,
        url: str,
        ref: Optional[str] = None,
        scan_id: Optional[str] = None,
        progress_cb: Optional[Callable[[str, dict], None]] = None,
    ) -> RepoScanReport:
        sid = scan_id or str(uuid.uuid4())[:12]
        if progress_cb:
            progress_cb("reposcan.progress", {"scan_id": sid, "phase": "cloning", "pct": 10})
        ctx = clone_and_load(url, ref=ref)
        return self.scan_context(ctx, scan_id=sid, progress_cb=progress_cb)
