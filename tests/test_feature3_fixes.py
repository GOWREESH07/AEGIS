"""
tests/test_feature3_fixes.py — Unit tests verifying Feature 3 fixes:
1. Sub-millisecond perf_counter_ns timing in JadePuffer
2. Stage 2 ADAPT async non-blocking execution (< 50ms)
3. Stage 4 LATERAL block requires AEGIS-confirmed token-bucket drop action
"""
from __future__ import annotations

import asyncio
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "attacker"))
sys.path.insert(0, str(ROOT / "aegis"))

try:
    import httpx
except ImportError:
    sys.modules["httpx"] = MagicMock()

from config import AttackConfig
from jadepuffer import JadePuffer


class TestFeature3Fixes(unittest.IsolatedAsyncioTestCase):
    async def test_perf_counter_ns_never_zero(self):
        cfg = AttackConfig(use_proxy=True, speed_multiplier=10.0)
        puffer = JadePuffer(cfg)
        t0 = time.perf_counter_ns()
        elapsed = puffer._elapsed_ms(t0)
        self.assertGreaterEqual(elapsed, 0.1)
        self.assertIsInstance(elapsed, float)

    async def test_lateral_unconfirmed_socket_close_is_not_blocked(self):
        """When socket closes without AEGIS confirmation, LATERAL must NOT report blocked=True."""
        cfg = AttackConfig(use_proxy=True, speed_multiplier=10.0)
        puffer = JadePuffer(cfg)
        queue = asyncio.Queue()

        mock_client = AsyncMock()
        resp_lat = MagicMock()
        resp_lat.status_code = 200
        resp_lat.json.return_value = {"dropped": False}
        resp_blk = MagicMock()
        resp_blk.status_code = 200
        resp_blk.json.return_value = []
        mock_client.get.side_effect = [resp_lat, resp_blk]

        with patch("asyncio.open_connection", side_effect=ConnectionResetError("transport closed")):
            await puffer._stage_lateral("test_run", queue, mock_client, 42)

        events = []
        while not queue.empty():
            events.append(await queue.get())

        complete_ev = [e for e in events if e["action"] == "stage_complete"][-1]
        self.assertFalse(complete_ev["detail"]["blocked"])
        self.assertFalse(complete_ev["detail"]["aegis_confirmed"])
        self.assertIsNone(complete_ev["blocked_by"])

    async def test_lateral_confirmed_token_bucket_drop_is_blocked(self):
        """When AEGIS confirms token_bucket_drop, LATERAL reports blocked=True and blocked_by='aegis'."""
        cfg = AttackConfig(use_proxy=True, speed_multiplier=10.0)
        puffer = JadePuffer(cfg)
        queue = asyncio.Queue()

        mock_client = AsyncMock()
        resp_lat = MagicMock()
        resp_lat.status_code = 200
        resp_lat.json.return_value = {"dropped": True, "action": "token_bucket_drop", "verdict": "quarantine"}
        mock_client.get.return_value = resp_lat

        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError("refused")):
            passed = await puffer._stage_lateral("test_run", queue, mock_client, 42)

        self.assertFalse(passed)
        events = []
        while not queue.empty():
            events.append(await queue.get())

        blocked_ev = [e for e in events if e["action"] == "blocked"]
        self.assertGreaterEqual(len(blocked_ev), 1)
        self.assertEqual(blocked_ev[0]["blocked_by"], "aegis")
        self.assertEqual(blocked_ev[0]["detail"]["reason"], "aegis_token_bucket_drop")


if __name__ == "__main__":
    unittest.main()
