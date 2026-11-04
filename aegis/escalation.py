"""
aegis/escalation.py — Human Escalation Queue for Grey-Zone & High-Impact Verdicts (Feature 5.2, Hardened in v2.1).

Grey-zone verdicts (`0.35 <= confidence < 0.55`) and high-impact actions are queued for
one-click operator approval/dismissal in the Defense Console.
While a verdict waits in the queue (`status == "pending"`), traffic is governed by
`pending_policy` (default: `"provisional_block"`, configurable via `AEGIS_ESCALATION_PENDING_POLICY`
to `"provisional_block"`, `"provisional_ratelimit"`, or `"allow"`).
If no human acts before `timeout_seconds`, `timeout_action` (default `"block"`) is auto-enforced.
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class EscalationItem(BaseModel):
    escalation_id: str
    source_ip: str
    subnet: str
    stage: int
    proposed_action: str
    pending_policy: str = "provisional_block"  # "provisional_block" | "provisional_ratelimit" | "allow"
    timeout_action: str = "block"
    is_grey_zone: bool = False
    confidence: float
    reason: str
    status: str = "pending"  # "pending" | "approved" | "dismissed" | "auto_enforced"
    created_at: float
    expires_at: float
    resolved_at: Optional[float] = None


class EscalationManager:
    GREY_ZONE_MIN: float = 0.35
    GREY_ZONE_MAX: float = 0.55

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        default_action: str = "block",
        pending_policy: Optional[str] = None,
        grey_zone_min: float = 0.35,
        grey_zone_max: float = 0.55,
    ):
        self.timeout_seconds = timeout_seconds
        self.default_action = default_action
        self.pending_policy = pending_policy or os.environ.get(
            "AEGIS_ESCALATION_PENDING_POLICY", "provisional_block"
        )
        self.grey_zone_min = grey_zone_min
        self.grey_zone_max = grey_zone_max
        self._items: Dict[str, EscalationItem] = {}

    def is_in_grey_zone(self, confidence: float) -> bool:
        return self.grey_zone_min <= confidence < self.grey_zone_max

    def _prune_and_apply_timeouts(self) -> None:
        now = time.time()
        for item in self._items.values():
            if item.status == "pending" and now >= item.expires_at:
                item.status = "auto_enforced"
                item.resolved_at = now

    def enqueue_if_needed(
        self,
        source_ip: str,
        stage: int,
        confidence: float,
        proposed_action: str = "provisional_block",
        reason: Optional[str] = None,
    ) -> Optional[EscalationItem]:
        self._prune_and_apply_timeouts()
        in_grey = self.is_in_grey_zone(confidence)
        high_impact = confidence >= 0.88 or stage in (4, 5, 6, 8, 9)
        if not in_grey and not high_impact:
            return None

        # Avoid duplicate pending escalations for the same IP + stage
        for existing in self._items.values():
            if existing.source_ip == source_ip and existing.stage == stage and existing.status == "pending":
                return existing

        parts = source_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else f"{source_ip}/32"
        now = time.time()
        esc_id = f"esc_{str(uuid.uuid4())[:8]}"
        if reason is None:
            if in_grey:
                reason = (
                    f"Grey-zone confidence ({confidence:.2f} in [{self.grey_zone_min:.2f}, {self.grey_zone_max:.2f})); "
                    f"traffic held under {self.pending_policy} pending operator review or auto-timeout ({self.default_action})"
                )
            else:
                reason = "High-impact autonomous action (subnet isolation / critical stage)"

        item = EscalationItem(
            escalation_id=esc_id,
            source_ip=source_ip,
            subnet=subnet,
            stage=stage,
            proposed_action=proposed_action,
            pending_policy=self.pending_policy,
            timeout_action=self.default_action,
            is_grey_zone=in_grey,
            confidence=round(confidence, 3),
            reason=reason,
            status="pending",
            created_at=now,
            expires_at=now + self.timeout_seconds,
        )
        self._items[esc_id] = item
        return item

    # Backwards-compatible alias
    enqueue_if_high_impact = enqueue_if_needed

    def resolve(self, escalation_id: str, decision: str) -> Optional[EscalationItem]:
        self._prune_and_apply_timeouts()
        item = self._items.get(escalation_id)
        if not item:
            return None
        item.status = "approved" if decision.lower() in ("approve", "approved") else "dismissed"
        item.resolved_at = time.time()
        return item

    def list_items(self) -> List[Dict[str, Any]]:
        self._prune_and_apply_timeouts()
        ordered = sorted(self._items.values(), key=lambda x: x.created_at, reverse=True)
        return [x.model_dump() for x in ordered[:25]]

    def clear(self) -> None:
        self._items.clear()

