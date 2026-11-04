"""
reposcan/main.py — FastAPI service for Repository AI-Attack Proneness Scanner.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

from cloner import validate_github_url
from engine import RepoScannerEngine
from models import RepoScanReport, RepoScanRequest
from report_export import render_markdown_report, render_pdf_bytes


DB_PATH = os.environ.get("REPOSCAN_DB_PATH", "/data/reposcan.db")
FIXTURES_ROOT = Path(os.environ.get("REPOSCAN_FIXTURES_ROOT", "/app/fixtures"))

app = FastAPI(title="AEGIS RepoScan Service", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = RepoScannerEngine(db_path=DB_PATH)
_in_memory_reports: Dict[str, RepoScanReport] = {}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "aegis-reposcan"}


@app.post("/api/reposcan")
async def start_reposcan(req: RepoScanRequest):
    try:
        normalized_url, owner, repo = validate_github_url(req.url)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    scan_id = str(uuid.uuid4())[:12]
    loop = asyncio.get_running_loop()

    # Built-in support for scanning bundled demo fixtures (`https://github.com/aegis-demo/vulnerable_repo` or `clean_repo`)
    fixture_dir = None
    if req.local_path and Path(req.local_path).exists():
        fixture_dir = Path(req.local_path)
    elif owner == "aegis-demo" and (FIXTURES_ROOT / repo).exists():
        fixture_dir = FIXTURES_ROOT / repo

    try:
        if fixture_dir is not None:
            report = await loop.run_in_executor(
                None,
                scanner.scan_local_directory,
                fixture_dir,
                normalized_url,
                scan_id,
                None,
            )
        else:
            report = await loop.run_in_executor(
                None,
                scanner.scan_github_url,
                normalized_url,
                req.ref,
                scan_id,
                None,
            )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    _in_memory_reports[report.scan_id] = report
    return {"scan_id": report.scan_id, "report": report}


@app.get("/api/reposcan/{scan_id}", response_model=RepoScanReport)
async def get_reposcan(scan_id: str):
    rep = _in_memory_reports.get(scan_id) or scanner.storage.get_by_scan_id(scan_id)
    if rep is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return rep


@app.get("/api/reposcan/{scan_id}/report.md")
async def get_reposcan_markdown(scan_id: str):
    rep = _in_memory_reports.get(scan_id) or scanner.storage.get_by_scan_id(scan_id)
    if rep is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    md = render_markdown_report(rep)
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="reposcan_{scan_id}.md"'},
    )


@app.get("/api/reposcan/{scan_id}/report.pdf")
async def get_reposcan_pdf(scan_id: str):
    rep = _in_memory_reports.get(scan_id) or scanner.storage.get_by_scan_id(scan_id)
    if rep is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    md = render_markdown_report(rep)
    pdf_bytes = render_pdf_bytes(f"AEGIS RepoScan Report - {rep.repo_owner}/{rep.repo_name}", md)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="reposcan_{scan_id}.pdf"'},
    )
