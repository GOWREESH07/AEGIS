"""
reposcan/analysts/ai_surface_analyst.py — AI-Surface Analyst (weight 1.5).
"""
from __future__ import annotations

from analysts.base import BaseRepoAnalyst
from checks.ai_surface_checks import AI_SURFACE_CHECKS


class AISurfaceAnalyst(BaseRepoAnalyst):
    analyst_key = "ai_surface"

    def __init__(self):
        self.checks = list(AI_SURFACE_CHECKS)
