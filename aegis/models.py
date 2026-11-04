from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class TrafficFeatures(BaseModel):
    source_ip: str
    timestamp: float
    requests_per_sec: float
    distinct_endpoints: int
    content_type_sequence: List[str]
    injection_regex_hits: int
    packets_per_sec: float
    window_seconds: int

class AnalystScore(BaseModel):
    analyst_name: str
    confidence: float
    reasoning: str
    features_used: List[str]

class CouncilVerdict(BaseModel):
    run_id: Optional[str] = None
    stage: Optional[int] = None
    scores: List[AnalystScore]
    weighted_confidence: float
    threshold: float
    action: str
    verdict_ms: float
    atlas_id: str = "AML.T0006"
    asi_id: str = "ASI01"

class DefenseEvent(BaseModel):
    event_type: str
    run_id: Optional[str] = None
    stage: Optional[int] = None
    source_ip: str = "unknown"
    verdict: Optional[CouncilVerdict] = None
    ts: float = 0.0
    atlas_id: str = "AML.T0006"
    asi_id: str = "ASI01"
    detail: Dict[str, Any] = {}

class TrialMetrics(BaseModel):
    trial_id: str
    run_id: str
    mode: str
    stage: int
    detection_latency_ms: float
    verdict: str
    confidence: float
    action: str
    attack_succeeded: bool
    ts: str
