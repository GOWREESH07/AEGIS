"""
reposcan/analysts/cicd_analyst.py — CI/CD & Agent-Workflow Analyst (weight 1.5).
"""
from __future__ import annotations

from analysts.base import BaseRepoAnalyst
from checks.cicd_checks import CICD_CHECKS


class CICDAnalyst(BaseRepoAnalyst):
    analyst_key = "cicd"

    def __init__(self):
        self.checks = list(CICD_CHECKS)
