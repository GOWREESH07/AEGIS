"""
aegis/guardrail.py — Pluggable Heuristic Guardrail (rule-based) (Feature 5.1) +
MITRE ATLAS & OWASP ASI Stage Tag Mapper (Feature 5.3).

Provides a clean pluggable `GuardrailClassifier` protocol interface:
- `RegexFastPathClassifier`: fast regex + hidden Unicode rule matcher
- `HeuristicRuleGuardrail` (aliased as `LocalHeuristicModelClassifier`): deterministic
  weighted-token heuristic guardrail (rule-based) for adversarial prompt injection,
  tool poisoning, and shell/credential exfiltration.
- `PluggableGuardrail`: combines the fast regex path and the heuristic guardrail (rule-based)
  behind a unified interface so a learned model can be plugged in later without changing callers.
"""
from __future__ import annotations

import math
import re
from typing import Dict, List, Protocol, Tuple


STAGE_TAXONOMY_TAGS: Dict[int, Tuple[str, str]] = {
    1: ("AML.T0006", "ASI01"),     # RECON — Active Scanning / Goal Hijack Recon
    2: ("AML.T0043", "ASI05"),     # ADAPT — Craft Adversarial Data / Parser Probing
    3: ("AML.T0051", "ASI01"),     # AILM — LLM Prompt Injection
    4: ("AML.T0029", "ASI02"),     # LATERAL — Denial of Service / Internal Flood
    5: ("AML.T0048", "ASI05"),     # EXEC — External Harms / Payload Execution
    6: ("AML.T0054", "ASI02"),     # MCP_POISON — LLM Plugin/Tool Compromise
    7: ("AML.T0051.001", "ASI06"), # RAG_INJECT — Indirect Prompt Injection
    8: ("AML.T0010", "ASI04"),     # SLOPSQUAT — ML Supply Chain Compromise
    9: ("AML.T0055", "ASI10"),     # CRED_HARVEST — Unsecured Credentials
}


def get_stage_tags(stage: int | None) -> Tuple[str, str]:
    return STAGE_TAXONOMY_TAGS.get(stage or 1, ("AML.T0006", "ASI01"))


class GuardrailClassifier(Protocol):
    def score_text(self, text: str) -> float:
        """Return a risk score in [0.0, 1.0] that *text* is an injection/attack payload."""
        ...


class RegexFastPathClassifier:
    def __init__(self):
        self.pattern = re.compile(
            r"ignore previous|system prompt|jailbreak|<script|UNION SELECT|DROP TABLE|"
            r"eval\(|base64_decode|__import__|payload_execution|exec_payload|lock_staging|"
            r"mcp_tool_registration|rag_document_ingest|slopsquat_install|cred_harvest|"
            r"~\/\.claude|~\/\.gemini|\.env|\u200b|\u200c|\u200d|\u2060|\ufeff|[\u202a-\u202e]|[\u2066-\u2069]",
            re.IGNORECASE,
        )

    def score_text(self, text: str) -> float:
        if not text:
            return 0.0
        matches = self.pattern.findall(text)
        if not matches:
            return 0.0
        return min(1.0, 0.85 + 0.05 * len(matches))


class HeuristicRuleGuardrail:
    """
    Deterministic weighted-token heuristic guardrail (rule-based) for adversarial
    prompt injection, indirect RAG overrides, and agent tool hijacking.
    A learned classifier implementing `GuardrailClassifier` can be plugged into
    `PluggableGuardrail` later.
    """

    TOKEN_WEIGHTS: Dict[str, float] = {
        "ignore": 1.6,
        "previous": 1.4,
        "instructions": 1.8,
        "system": 1.2,
        "override": 1.9,
        "reveal": 1.5,
        "config": 1.1,
        "exfiltrate": 2.4,
        "beacon": 2.0,
        "fetch": 1.1,
        "eval": 1.9,
        "base64_decode": 2.2,
        "union": 1.7,
        "select": 1.3,
        "payload_execution": 2.8,
        "lock_staging": 2.8,
        "id_rsa": 2.5,
        ".claude": 2.3,
        ".gemini": 2.3,
        "hallucinated": 2.1,
        "slopsquat": 2.4,
    }
    BIAS: float = -2.6

    def score_text(self, text: str) -> float:
        if not text:
            return 0.0
        low = text.lower()
        logit = self.BIAS
        for tok, w in self.TOKEN_WEIGHTS.items():
            if tok in low:
                logit += w
        # Hidden Unicode boost
        if any(ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF) or 0x202A <= ord(c) <= 0x202E for c in text):
            logit += 2.5
        prob = 1.0 / (1.0 + math.exp(-max(-10.0, min(10.0, logit))))
        return round(prob, 4)


# Backwards-compatible alias
LocalHeuristicModelClassifier = HeuristicRuleGuardrail


class PluggableGuardrail:
    """
    Combines the fast regex path with the heuristic guardrail (rule-based) behind
    a unified pluggable interface (`GuardrailClassifier`). A learned model can be
    plugged in later via `classifier=...`.
    """

    def __init__(self, use_local_model: bool = True, classifier: GuardrailClassifier | None = None):
        self.fast_regex = RegexFastPathClassifier()
        self.local_model: GuardrailClassifier | None = (
            classifier if classifier is not None else (HeuristicRuleGuardrail() if use_local_model else None)
        )

    def evaluate(self, text: str, regex_hits: int = 0) -> float:
        fast_score = 1.0 if regex_hits > 0 else self.fast_regex.score_text(text)
        if fast_score >= 0.90 or self.local_model is None:
            return fast_score
        model_score = self.local_model.score_text(text)
        return max(fast_score, model_score)

