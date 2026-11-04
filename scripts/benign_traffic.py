#!/usr/bin/env python3
"""
benign_traffic.py — Benign traffic replay against AEGIS/target

Sends normal-looking browsing traffic to validate AEGIS doesn't
generate false positives on legitimate requests.

Usage:
    python scripts/benign_traffic.py [--requests 50] [--delay 0.5]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import time
from datetime import datetime, timezone

import httpx

AEGIS_URL = os.getenv("AEGIS_URL", "http://localhost:8000")

BENIGN_REQUESTS = [
    ("GET", "/api/ping", None, None),
    ("GET", "/api/status", None, None),
    ("GET", "/api/users", None, None),
    ("GET", "/api/config", None, None),
    ("GET", "/api/metrics", None, None),
    ("GET", "/api/reports", None, None),
    ("POST", "/api/flow/execute", "application/json", b'{"query": "status", "limit": 10}'),
    ("GET", "/api/ping", None, None),
    ("GET", "/api/v2/scan", None, None),
    ("GET", "/api/admin", None, None),
]


async def main(n: int, delay: float) -> None:
    blocked = 0
    errors = 0
    allowed = 0

    print(f"\nBenign traffic replay: {n} requests at {delay}s intervals")
    print(f"Target: {AEGIS_URL}\n")

    async with httpx.AsyncClient() as client:
        for i in range(n):
            method, path, ct, body = BENIGN_REQUESTS[i % len(BENIGN_REQUESTS)]
            url = AEGIS_URL + path
            headers = {"Content-Type": ct} if ct else {}
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]

            try:
                if method == "GET":
                    r = await client.get(url, headers=headers, timeout=5.0)
                else:
                    r = await client.post(url, content=body, headers=headers, timeout=5.0)

                if r.status_code in (403, 429):
                    blocked += 1
                    status_str = f"BLOCKED [{r.status_code}]"
                else:
                    allowed += 1
                    status_str = f"OK      [{r.status_code}]"

                print(f"  {ts}  {method:4s} {path:<30s} {status_str}")
            except Exception as exc:
                errors += 1
                print(f"  {ts}  {method:4s} {path:<30s} ERROR: {exc}")

            await asyncio.sleep(delay)

    total = n - errors
    fp_rate = blocked / total if total > 0 else 0.0
    print(f"\nResults:")
    print(f"  Requests:  {n}")
    print(f"  Allowed:   {allowed}")
    print(f"  Blocked:   {blocked}")
    print(f"  Errors:    {errors}")
    print(f"  FP Rate:   {fp_rate:.2%}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()
    asyncio.run(main(args.requests, args.delay))
