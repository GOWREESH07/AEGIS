"""
reposcan/analysts/supply_chain_analyst.py — Supply-Chain Analyst (weight 1.0).
"""
from __future__ import annotations

from typing import Optional
from analysts.base import BaseRepoAnalyst
from checks.supply_chain_checks import build_supply_chain_checks
from registry import RegistryClient


class SupplyChainAnalyst(BaseRepoAnalyst):
    analyst_key = "supply_chain"

    def __init__(self, registry_client: Optional[RegistryClient] = None):
        self.checks = build_supply_chain_checks(registry_client)
