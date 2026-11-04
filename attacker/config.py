"""
config.py — AttackConfig for JadePuffer-sim

All configurable parameters for the simulation run.
"""
from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field


class AttackConfig(BaseModel):
    target_host: str = Field(
        default="http://aegis:8000",
        description="Attack target — goes through AEGIS proxy when use_proxy=True",
    )
    target_direct: str = Field(
        default="http://target:8001",
        description="Direct target URL, bypassing AEGIS",
    )
    use_proxy: bool = Field(
        default=True,
        description="If False, bypass AEGIS and hit target directly (baseline demo)",
    )
    speed_multiplier: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        description="1.0 = normal speed; 2.0 = twice as fast",
    )
    mutation_seed: int = Field(
        default=42,
        description="RNG seed for payload mutations on second run",
    )
    stages: List[int] = Field(
        default=[1, 2, 3, 4, 5],
        description="Which stages to execute (1=Recon, 2=AdaptParse, 3=AILM, 4=Lateral, 5=Exec)",
    )
    mode: str = Field(
        default="once",
        description='"once" | "repeat" — repeat runs mutated signatures',
    )
    internal_host: str = Field(default="target", description="Host for lateral movement")
    internal_port: int = Field(default=8002, description="Port for lateral movement")
    staging_path: str = Field(
        default="/shared/staging",
        description="Volume-mounted path shared with target service",
    )
