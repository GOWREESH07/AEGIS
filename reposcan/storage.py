"""
reposcan/storage.py — SQLite persistence for `scans`, `findings`, and `registry_cache`.
Re-scanning the same commit SHA returns the cached report.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional
from models import RepoScanReport


class ScanStorage:
    def __init__(self, db_path: str = "/data/reposcan.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self) -> None:
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        url TEXT,
                        commit_sha TEXT,
                        proneness_pct REAL,
                        risk_band TEXT,
                        scanned_at TEXT,
                        report_json TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT,
                        check_id TEXT,
                        analyst TEXT,
                        severity TEXT,
                        file TEXT,
                        line INTEGER,
                        asi_ids TEXT,
                        finding_json TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS registry_cache (
                        cache_key TEXT PRIMARY KEY,
                        ecosystem TEXT,
                        package_name TEXT,
                        exists_flag INTEGER,
                        payload_json TEXT,
                        updated_at REAL
                    )
                    """
                )
                conn.commit()
        except Exception:
            pass

    def save_report(self, report: RepoScanReport) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scans
                    (scan_id, url, commit_sha, proneness_pct, risk_band, scanned_at, report_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report.scan_id,
                        report.url,
                        report.commit_sha,
                        report.proneness_pct,
                        report.risk_band,
                        report.scanned_at,
                        report.model_dump_json(),
                    ),
                )
                conn.execute("DELETE FROM findings WHERE scan_id = ?", (report.scan_id,))
                for f in report.findings:
                    conn.execute(
                        """
                        INSERT INTO findings
                        (scan_id, check_id, analyst, severity, file, line, asi_ids, finding_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            report.scan_id,
                            f.check_id,
                            f.analyst,
                            f.severity,
                            f.file,
                            f.line,
                            ",".join(f.asi_ids),
                            f.model_dump_json(),
                        ),
                    )
                conn.commit()
        except Exception:
            pass

    def get_by_scan_id(self, scan_id: str) -> Optional[RepoScanReport]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,))
                row = cur.fetchone()
                if row and row[0]:
                    return RepoScanReport.model_validate_json(row[0])
        except Exception:
            pass
        return None

    def get_by_commit_sha(self, url: str, commit_sha: str) -> Optional[RepoScanReport]:
        if not commit_sha or commit_sha == "0" * 40:
            return None
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    "SELECT report_json FROM scans WHERE url = ? AND commit_sha = ? ORDER BY scanned_at DESC LIMIT 1",
                    (url, commit_sha),
                )
                row = cur.fetchone()
                if row and row[0]:
                    rep = RepoScanReport.model_validate_json(row[0])
                    rep.cached = True
                    return rep
        except Exception:
            pass
        return None
