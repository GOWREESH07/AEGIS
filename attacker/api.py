"""
api.py — JadePuffer-sim HTTP API

FastAPI service exposing endpoints to trigger and control attack simulation runs.
The Attack Console frontend communicates with this service.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config import AttackConfig
from jadepuffer import JadePuffer

# ─────────────────────────────────────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────────────────────────────────────

_current_run: dict[str, Any] | None = None
_current_task: asyncio.Task | None = None
_current_puffer: JadePuffer | None = None
_event_queue: asyncio.Queue = asyncio.Queue()
_ws_clients: set[WebSocket] = set()
_recent_attacker_events: list[dict[str, Any]] = []


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket broadcaster
# ─────────────────────────────────────────────────────────────────────────────

async def _broadcast_loop() -> None:
    """Drain the event queue and broadcast each event to all WS clients."""
    while True:
        try:
            event = await asyncio.wait_for(_event_queue.get(), timeout=1.0)
            _recent_attacker_events.append(event)
            if len(_recent_attacker_events) > 250:
                del _recent_attacker_events[:-250]
            if _ws_clients:
                message = json.dumps(event)
                dead: set[WebSocket] = set()
                for ws in list(_ws_clients):
                    try:
                        await ws.send_text(message)
                    except Exception:
                        dead.add(ws)
                _ws_clients.difference_update(dead)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            break


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    broadcast_task = asyncio.create_task(_broadcast_loop())
    yield
    broadcast_task.cancel()
    try:
        await broadcast_task
    except asyncio.CancelledError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="JadePuffer-sim API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    speed_multiplier: float = 1.0
    mutation_seed: int = 42
    stages: list[int] = [1, 2, 3, 4, 5]
    mode: str = "once"
    use_proxy: bool = True


class RunResponse(BaseModel):
    run_id: str
    started_at: str


class StatusResponse(BaseModel):
    run_id: str | None
    stage: int | None
    status: str
    started_at: str | None


# ─────────────────────────────────────────────────────────────────────────────
# Background task runner
# ─────────────────────────────────────────────────────────────────────────────

async def _execute_run(config: AttackConfig, run_id: str) -> None:
    global _current_run
    puffer = _current_puffer

    if config.mode == "repeat":
        seed = config.mutation_seed
        run_count = 0
        while not puffer._stop_event.is_set():
            puffer._stop_event.clear()
            await puffer.run(_event_queue, run_id=f"{run_id}_{run_count}", mutation_seed=seed)
            seed += 1
            run_count += 1
            await asyncio.sleep(2.0)
    else:
        await puffer.run(_event_queue, run_id=run_id, mutation_seed=config.mutation_seed)

    if _current_run:
        _current_run["status"] = "completed"


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/run", response_model=RunResponse)
async def start_run(req: RunRequest):
    global _current_run, _current_task, _current_puffer

    if _current_run and _current_run.get("status") == "running":
        raise HTTPException(status_code=409, detail="A run is already in progress. POST /api/stop first.")

    run_id = str(uuid.uuid4())[:8]
    target_proxy = os.getenv("TARGET_PROXY_URL", "http://aegis:8000")
    target_direct = os.getenv("TARGET_DIRECT_URL", "http://target:8001")
    internal_host = os.getenv("INTERNAL_HOST", "target")
    internal_port = int(os.getenv("INTERNAL_PORT", "8002"))
    staging_path = os.getenv("STAGING_PATH", "/shared/staging")

    config = AttackConfig(
        target_host=target_proxy,
        target_direct=target_direct,
        use_proxy=req.use_proxy,
        speed_multiplier=req.speed_multiplier,
        mutation_seed=req.mutation_seed,
        stages=req.stages,
        mode=req.mode,
        internal_host=internal_host,
        internal_port=internal_port,
        staging_path=staging_path,
    )

    _recent_attacker_events.clear()
    _current_puffer = JadePuffer(config)
    started_at = _utcnow()
    _current_run = {
        "run_id": run_id,
        "status": "running",
        "started_at": started_at,
        "stage": None,
    }
    _current_task = asyncio.create_task(_execute_run(config, run_id))
    return RunResponse(run_id=run_id, started_at=started_at)


@app.post("/api/stop")
async def stop_run():
    global _current_run, _current_task, _current_puffer

    if not _current_run or _current_run.get("status") != "running":
        raise HTTPException(status_code=404, detail="No run in progress.")

    if _current_puffer:
        _current_puffer.stop()
    if _current_task and not _current_task.done():
        _current_task.cancel()

    _current_run["status"] = "stopped"
    return {"status": "stopped", "run_id": _current_run["run_id"]}


@app.get("/api/status", response_model=StatusResponse)
async def get_status():
    if not _current_run:
        return StatusResponse(run_id=None, stage=None, status="idle", started_at=None)
    return StatusResponse(
        run_id=_current_run["run_id"],
        stage=_current_run.get("stage"),
        status=_current_run["status"],
        started_at=_current_run["started_at"],
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "jadepuffer-api"}


@app.get("/api/events")
async def get_attacker_events():
    return _recent_attacker_events


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket — stream attack events to Attack Console
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    # Send current run status on connect
    await websocket.send_text(json.dumps({
        "run_id": _current_run["run_id"] if _current_run else None,
        "stage": 0,
        "stage_name": "CONNECTED",
        "ts": _utcnow(),
        "action": "connected",
        "detail": {"status": _current_run["status"] if _current_run else "idle"},
        "blocked_by": None,
    }))
    try:
        while True:
            # Keep connection alive — send periodic pings
            await asyncio.sleep(15)
            await websocket.send_text(json.dumps({"action": "ping", "ts": _utcnow()}))
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)
    except Exception:
        _ws_clients.discard(websocket)


if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8003, reload=False)
