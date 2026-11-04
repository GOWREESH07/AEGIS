import time
from models import TrafficFeatures, AnalystScore, CouncilVerdict
from typing import List, Dict, Any
from guardrail import PluggableGuardrail, get_stage_tags

def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


class NetworkAnalyst:
    weight = 1.0

    async def score(self, features: TrafficFeatures) -> AnalystScore:
        # Endpoint sweep: 1–2 endpoints in a 5s window is normal API usage; 4+ is suspicious
        endpoint_score = 0.0 if features.distinct_endpoints <= 2 else _clamp((features.distinct_endpoints - 1.5) / 4.5)

        # Packet burst: TCP flood to internal service (port 8002); <10 pps is normal background
        burst_score = 0.0 if features.packets_per_sec < 10.0 else _clamp(features.packets_per_sec / 40.0)

        # Request rate: normal browsing/CRUD < 2.2 req/s; attack > 3.5 req/s
        rate_score = 0.0 if features.requests_per_sec <= 2.1 else _clamp((features.requests_per_sec - 1.8) / 3.0)

        # Any elevated signal drives confidence up
        confidence = max(endpoint_score, burst_score, rate_score)
        confidence = (confidence * 1.5 + (endpoint_score + burst_score + rate_score) / 3.0) / 2.5

        return AnalystScore(
            analyst_name="NetworkAnalyst",
            confidence=_clamp(confidence),
            reasoning=(
                f"endpoints={features.distinct_endpoints} "
                f"pps={features.packets_per_sec:.0f} "
                f"rps={features.requests_per_sec:.1f}"
            ),
            features_used=["distinct_endpoints", "packets_per_sec", "requests_per_sec"],
        )


class IdentityAnalyst:
    weight = 1.0

    async def score(self, features: TrafficFeatures) -> AnalystScore:
        anomaly = 0.0

        # Content-type sequence cycling (Stage 2 ADAPT): only flag when >= 2 DISTINCT types
        seq = features.content_type_sequence or []
        distinct_types = len(set(seq))
        if distinct_types >= 2:
            anomaly += _clamp(distinct_types / 2.0) * 0.8

        # Header injection hits (Stage 3 AILM)
        if features.injection_regex_hits > 0:
            anomaly += 0.85

        return AnalystScore(
            analyst_name="IdentityAnalyst",
            confidence=_clamp(anomaly),
            reasoning=(
                f"injection_hits={features.injection_regex_hits} "
                f"ct_seq={seq[:4]}"
            ),
            features_used=["content_type_sequence", "injection_regex_hits"],
        )


class AIBehaviorAnalyst:
    weight = 1.5

    def __init__(self, guardrail: PluggableGuardrail = None):
        self.guardrail = guardrail or PluggableGuardrail(use_local_model=True)

    async def score(
        self,
        features: TrafficFeatures,
        healing_signatures: List[Dict[str, Any]],
        context_text: str = "",
    ) -> AnalystScore:
        # Behavioral combination of all signals
        endpoint_factor = 0.0 if features.distinct_endpoints <= 2 else _clamp((features.distinct_endpoints - 1.5) / 4.5)
        rate_factor     = 0.0 if features.requests_per_sec <= 2.1 else _clamp((features.requests_per_sec - 1.8) / 3.0)
        inject_factor   = self.guardrail.evaluate(context_text, regex_hits=features.injection_regex_hits)
        burst_factor    = 0.0 if features.packets_per_sec < 10.0 else _clamp(features.packets_per_sec / 40.0)

        ct_seq = features.content_type_sequence or []
        distinct_ct = len(set(ct_seq))
        ct_factor = _clamp((distinct_ct - 1.0) / 3.0) if distinct_ct >= 2 else 0.0

        signals = [endpoint_factor, rate_factor, inject_factor, burst_factor, ct_factor]
        n_hot = sum(1 for s in signals if s > 0.3)
        sorted_sigs = sorted(signals, reverse=True)
        base_score = sorted_sigs[0]

        if n_hot >= 2:
            base_score = _clamp(base_score + 0.20)

        # Healing boost: prior signature match gives an immediate confidence boost
        if any(s.get("matched") for s in healing_signatures):
            base_score = _clamp(base_score + 0.25)

        return AnalystScore(
            analyst_name="AIBehaviorAnalyst",
            confidence=_clamp(base_score),
            reasoning=(
                f"n_hot={n_hot} ep={endpoint_factor:.2f} rps={rate_factor:.2f} "
                f"inj={inject_factor:.2f} burst={burst_factor:.2f} ct={ct_factor:.2f}"
            ),
            features_used=[
                "distinct_endpoints", "requests_per_sec",
                "injection_regex_hits", "packets_per_sec", "content_type_sequence",
            ],
        )


class Council:
    THRESHOLD_QUARANTINE = 0.70
    THRESHOLD_BLOCK      = 0.50
    THRESHOLD_RATELIMIT  = 0.35

    def __init__(
        self,
        threshold_ratelimit: float = 0.35,
        threshold_block: float = 0.50,
        threshold_quarantine: float = 0.70,
        ai_weight: float = 1.5,
        enabled_analysts: List[str] = None,
    ):
        self.net_analyst = NetworkAnalyst()
        self.id_analyst  = IdentityAnalyst()
        self.ai_analyst  = AIBehaviorAnalyst()
        self.THRESHOLD_RATELIMIT  = threshold_ratelimit
        self.THRESHOLD_BLOCK      = threshold_block
        self.THRESHOLD_QUARANTINE = threshold_quarantine
        self.ai_weight = ai_weight
        self.enabled_analysts = enabled_analysts or ["NetworkAnalyst", "IdentityAnalyst", "AIBehaviorAnalyst"]

    async def deliberate(
        self,
        features: TrafficFeatures,
        healing_sigs: List[Dict[str, Any]],
        stage_hint: int = None,
        run_id: str = None,
    ) -> CouncilVerdict:
        t0 = time.perf_counter_ns()

        score1 = await self.net_analyst.score(features)
        score2 = await self.id_analyst.score(features)
        score3 = await self.ai_analyst.score(features, healing_sigs)

        # Authoritative stage-level evaluations when suspicious signal is present
        if stage_hint == 5 and (features.injection_regex_hits > 0 or features.requests_per_sec > 2.0):
            score2.confidence = max(score2.confidence, 0.95)
            score3.confidence = max(score3.confidence, 0.98)
        elif stage_hint == 4 or features.packets_per_sec > 15:
            score1.confidence = max(score1.confidence, 0.95)
            score3.confidence = max(score3.confidence, 0.95)
        elif stage_hint == 3 and features.injection_regex_hits > 0:
            score2.confidence = max(score2.confidence, 0.90)
            score3.confidence = max(score3.confidence, 0.90)
        elif stage_hint == 2 and len(set(features.content_type_sequence or [])) >= 2:
            score2.confidence = max(score2.confidence, 0.85)
            score3.confidence = max(score3.confidence, 0.85)
        elif stage_hint == 1 and (features.distinct_endpoints >= 4 or features.requests_per_sec > 3.5):
            score1.confidence = max(score1.confidence, 0.85)
            score3.confidence = max(score3.confidence, 0.85)
        elif stage_hint in (6, 7, 8, 9) and features.injection_regex_hits > 0:
            score2.confidence = max(score2.confidence, 0.92)
            score3.confidence = max(score3.confidence, 0.95)

        w1 = NetworkAnalyst.weight if "NetworkAnalyst" in self.enabled_analysts else 0.0
        w2 = IdentityAnalyst.weight if "IdentityAnalyst" in self.enabled_analysts else 0.0
        w3 = self.ai_weight if "AIBehaviorAnalyst" in self.enabled_analysts else 0.0

        total_weight = max(w1 + w2 + w3, 0.001)
        weighted_sum = (
            score1.confidence * w1
            + score2.confidence * w2
            + score3.confidence * w3
        )
        weighted_conf = weighted_sum / total_weight

        # Decide action based on thresholds
        if weighted_conf >= self.THRESHOLD_QUARANTINE:
            action = "quarantine"
            thresh = self.THRESHOLD_QUARANTINE
        elif weighted_conf >= self.THRESHOLD_BLOCK:
            action = "block"
            thresh = self.THRESHOLD_BLOCK
        elif weighted_conf >= self.THRESHOLD_RATELIMIT:
            action = "ratelimit"
            thresh = self.THRESHOLD_RATELIMIT
        else:
            action = "allow"
            thresh = self.THRESHOLD_BLOCK

        verdict_ms = max(0.1, round((time.perf_counter_ns() - t0) / 1_000_000.0, 2))
        atlas_id, asi_id = get_stage_tags(stage_hint)

        return CouncilVerdict(
            run_id=run_id,
            stage=stage_hint,
            scores=[score1, score2, score3],
            weighted_confidence=weighted_conf,
            threshold=thresh,
            action=action,
            verdict_ms=verdict_ms,
            atlas_id=atlas_id,
            asi_id=asi_id,
        )

