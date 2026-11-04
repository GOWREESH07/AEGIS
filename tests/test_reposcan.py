"""
tests/test_reposcan.py — Comprehensive unit tests for RepoScan (Feature 1):
1. Vulnerable fixture scores >= 80%
2. Clean fixture scores < 20%
3. Individual checks A1–A8, B1–B6, C1–C9 verified
4. Scorer arithmetic matches hand calculation (`1 - Π(1 - sev*conf)` and weighted average + critical floor)
5. Safety test: scanner never executes or spawns repository code (`subprocess` mocked and verified)
6. URL validation rejects SSRF / non-GitHub hosts
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reposcan"))

from cloner import RepoContext, load_repo_context, validate_github_url
from engine import RepoScannerEngine
from models import Finding, SEVERITY_WEIGHTS
from registry import RegistryClient
from scorer import score_findings
from checks.cicd_checks import (
    CheckA1PwnRequest,
    CheckA2AIAgentActionUntrustedTrigger,
    CheckA3UntrustedInterpolation,
    CheckA4AIActionAllowAllUsers,
    CheckA5BroadWorkflowPermissions,
    CheckA6UnpinnedThirdPartyActions,
    CheckA7SharedCachePoisoning,
    CheckA8BroadPublishingSecrets,
)
from checks.supply_chain_checks import (
    CheckB1InstallScripts,
    CheckB2Slopsquatting,
    CheckB3Typosquatting,
    CheckB4VulnerableDependencies,
    CheckB5MissingLockfileOrUnpinned,
    CheckB6MissingDependabotAndSecurityMd,
)
from checks.ai_surface_checks import (
    CheckC1HiddenUnicodeInRules,
    CheckC2MaliciousInstructionDirectives,
    CheckC3UnsafeMCPConfig,
    CheckC4LLMOutputToDangerousSink,
    CheckC5PromptConcatenation,
    CheckC6UnconfirmedAgentTools,
    CheckC7UnsanitizedRAGIngestion,
    CheckC8HardcodedCredentialsOrEnv,
    CheckC9MissingPromptInjectionTests,
)


VULN_FIXTURE = ROOT / "tests" / "fixtures" / "vulnerable_repo"
CLEAN_FIXTURE = ROOT / "tests" / "fixtures" / "clean_repo"


class TestRepoScan(unittest.TestCase):
    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp_db.close()
        self.registry = RegistryClient(db_path=self.tmp_db.name, offline_fallback=True)
        self.engine = RepoScannerEngine(db_path=self.tmp_db.name, registry_client=self.registry)

    def test_vulnerable_fixture_scores_at_least_80_pct(self):
        report = self.engine.scan_local_directory(
            VULN_FIXTURE, url="https://github.com/aegis-demo/vulnerable_repo"
        )
        self.assertGreaterEqual(
            report.proneness_pct,
            80.0,
            f"Expected vulnerable_repo >= 80%, got {report.proneness_pct}% (findings: {[f.check_id for f in report.findings]})",
        )
        self.assertEqual(report.risk_band, "Critical")
        check_ids = {f.check_id for f in report.findings}
        for expected in ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "B1", "B2", "B3", "B4", "B5", "C1", "C2", "C3", "C4", "C5", "C7", "C8"):
            self.assertIn(expected, check_ids, f"Expected check {expected} to trigger on vulnerable_repo")

    def test_clean_fixture_scores_below_20_pct(self):
        report = self.engine.scan_local_directory(
            CLEAN_FIXTURE, url="https://github.com/aegis-demo/clean_repo"
        )
        self.assertLess(
            report.proneness_pct,
            20.0,
            f"Expected clean_repo < 20%, got {report.proneness_pct}% (findings: {[f.check_id for f in report.findings]})",
        )
        self.assertEqual(report.risk_band, "Low")

    def test_scorer_arithmetic_matches_by_hand(self):
        """
        Hand calculation check:
        - CICD: 1 high finding (0.30 * 1.0) -> score = 0.30
        - Supply Chain: 2 medium findings (0.15 * 1.0 each) -> score = 1 - (0.85 * 0.85) = 1 - 0.7225 = 0.2775
        - AI Surface: 1 high finding (0.30) + 1 medium finding (0.15) -> score = 1 - (0.70 * 0.85) = 1 - 0.595 = 0.405
        Weighted average = (0.30*1.5 + 0.2775*1.0 + 0.405*1.5) / 4.0
                         = (0.45 + 0.2775 + 0.6075) / 4.0
                         = 1.335 / 4.0 = 0.33375 -> 33.4%
        """
        findings = [
            Finding(
                check_id="A3", analyst="cicd", title="t", severity="high",
                severity_weight=0.30, confidence=1.0, file="a.yml", line=1,
                evidence="e", why_it_matters="w", asi_ids=["ASI01"]
            ),
            Finding(
                check_id="B3", analyst="supply_chain", title="t", severity="medium",
                severity_weight=0.15, confidence=1.0, file="package.json", line=1,
                evidence="e", why_it_matters="w", asi_ids=["ASI04"]
            ),
            Finding(
                check_id="B5", analyst="supply_chain", title="t", severity="medium",
                severity_weight=0.15, confidence=1.0, file="package.json", line=2,
                evidence="e", why_it_matters="w", asi_ids=["ASI04"]
            ),
            Finding(
                check_id="C3", analyst="ai_surface", title="t", severity="high",
                severity_weight=0.30, confidence=1.0, file=".mcp.json", line=1,
                evidence="e", why_it_matters="w", asi_ids=["ASI02"]
            ),
            Finding(
                check_id="C5", analyst="ai_surface", title="t", severity="medium",
                severity_weight=0.15, confidence=1.0, file="app.py", line=1,
                evidence="e", why_it_matters="w", asi_ids=["ASI01"]
            ),
        ]
        final_pct, raw_pct, floor_applied, band, arith, analysts = score_findings(findings)
        self.assertAlmostEqual(analysts[0].score, 0.30, places=4)
        self.assertAlmostEqual(analysts[1].score, 0.2775, places=4)
        self.assertAlmostEqual(analysts[2].score, 0.405, places=4)
        self.assertAlmostEqual(raw_pct, 33.4, places=1)
        self.assertAlmostEqual(final_pct, 33.4, places=1)
        self.assertFalse(floor_applied)
        self.assertEqual(band, "Moderate")

        # Now add a single critical finding and verify the 70% critical floor
        findings_with_crit = findings + [
            Finding(
                check_id="C1", analyst="ai_surface", title="crit", severity="critical",
                severity_weight=0.45, confidence=1.0, file=".cursorrules", line=1,
                evidence="e", why_it_matters="w", asi_ids=["ASI01"]
            )
        ]
        final_crit_pct, raw_crit_pct, floor_crit, band_crit, _, _ = score_findings(findings_with_crit)
        self.assertTrue(floor_crit)
        self.assertEqual(final_crit_pct, 70.0)
        self.assertEqual(band_crit, "High")

    def test_scanner_never_spawns_repository_code(self):
        """Mock subprocess.run / Popen / os.system / builtins.exec and assert none are called with repo paths or code."""
        import builtins
        import os

        real_exec = builtins.exec
        repo_path_str = str(VULN_FIXTURE.resolve())
        exec_calls_with_repo = []

        def guarded_exec(source, *args, **kwargs):
            src_str = str(source)
            if repo_path_str in src_str or "app.py" in src_str or "vulnerable_repo" in src_str:
                exec_calls_with_repo.append(src_str)
            return real_exec(source, *args, **kwargs)

        with (
            patch.object(subprocess, "run") as mock_run,
            patch.object(subprocess, "Popen") as mock_popen,
            patch.object(os, "system") as mock_system,
            patch.object(builtins, "exec", side_effect=guarded_exec),
        ):
            report = self.engine.scan_local_directory(
                VULN_FIXTURE, url="https://github.com/aegis-demo/vulnerable_repo"
            )
            self.assertGreaterEqual(report.proneness_pct, 80.0)
            mock_run.assert_not_called()
            mock_popen.assert_not_called()
            mock_system.assert_not_called()
            self.assertEqual(exec_calls_with_repo, [])

    def test_url_validation_blocks_ssrf_and_non_github(self):
        valid_url, owner, repo = validate_github_url("https://github.com/anthropics/claude-code.git")
        self.assertEqual(valid_url, "https://github.com/anthropics/claude-code")
        self.assertEqual(owner, "anthropics")
        self.assertEqual(repo, "claude-code")

        for bad_url in (
            "http://169.254.169.254/latest/meta-data",
            "https://evil.com/owner/repo",
            "https://github.com/owner/repo?foo=bar",
            "https://user:pass@github.com/owner/repo",
            "file:///etc/passwd",
        ):
            with self.assertRaises(ValueError):
                validate_github_url(bad_url)

    def test_c6_and_c9_checks_directly(self):
        ctx = RepoContext(
            root=Path("/tmp"),
            url="https://github.com/test/repo",
            owner="test",
            repo="repo",
            commit_sha="0" * 40,
            files={
                "agent_tools.py": (
                    "import subprocess\n"
                    "import openai\n"
                    "@tool\n"
                    "def run_bash(cmd: str):\n"
                    "    return subprocess.check_output(cmd, shell=True)\n"
                )
            },
            files_eligible=1,
            files_analysed=1,
        )
        c6_findings = CheckC6UnconfirmedAgentTools().run(ctx)
        c9_findings = CheckC9MissingPromptInjectionTests().run(ctx)
        self.assertEqual(len(c6_findings), 1)
        self.assertEqual(c6_findings[0].check_id, "C6")
        self.assertEqual(len(c9_findings), 1)
        self.assertEqual(c9_findings[0].check_id, "C9")


if __name__ == "__main__":
    unittest.main()
