from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import httpx
import redis.asyncio as redis
import time
import os
import json
import asyncio
from contextlib import asynccontextmanager
from typing import Set, Dict, Tuple

from surveillance import SurveillanceLayer
from council import Council
from response import ResponseEngine
from healing import HealingEngine
from metrics import MetricsDB
from models import DefenseEvent, TrialMetrics
from guardrail import get_stage_tags
from escalation import EscalationManager
from incident_report import generate_incident_markdown, generate_incident_pdf

# Globals
AEGIS_ENABLED = True
TARGET_URL = os.getenv("TARGET_URL", "http://target:8001")
ATTACKER_URL = os.getenv("ATTACKER_URL", "http://attacker:8003")
REPOSCAN_URL = os.getenv("REPOSCAN_URL", "http://reposcan:8004")

_reposcan_cache: Dict[str, dict] = {}
_recent_defense_events: list = []
escalation_mgr = EscalationManager(timeout_seconds=30.0)

redis_client = None
surveillance = None
council = None
responder = None
healer = None
metrics = None
http_client = None

connected_clients: Set[WebSocket] = set()

def infer_stage_from_traffic(method: str, path: str, headers: dict, features) -> int:
    """Authoritative mapping from request characteristics to JadePuffer kill-chain stage"""
    ctx = headers.get("x-forwarded-context", "").lower()
    ct = headers.get("content-type", "").lower()

    # Feature 4 optional AI attack stages (6–9)
    if "/api/mcp/register" in path or "mcp_tool" in ctx:
        return 6
    if "/api/rag/ingest" in path or "rag_document" in ctx:
        return 7
    if "/api/packages/install" in path or "slopsquat" in ctx:
        return 8
    if "/api/fs/read" in path or "cred_harvest" in ctx or ".claude" in ctx or ".gemini" in ctx:
        return 9

    # Stage 5: payload execution trigger (POST to /api/admin or payload execution header)
    if (method == "POST" and "/api/admin" in path) or "payload" in ctx or "exec" in ctx or "lock" in ctx or "payload_exec" in path:
        return 5

    # Stage 4: lateral TCP flood to internal service
    if features.packets_per_sec > 15:
        return 4

    # Stage 2: Adaptive parser cycling against /api/flow/execute or XML/octet payloads
    if "/api/flow/execute" in path or "xml" in ct or "octet" in ct:
        return 2

    # Stage 3: header injection
    if features.injection_regex_hits > 0 or "script" in ctx or "union" in ctx or "ignore" in ctx:
        return 3

    # Content-type sequence cycling
    seq = features.content_type_sequence or []
    if len(seq) >= 2 and len(set(seq)) >= 2:
        return 2

    # Stage 1: reconnaissance sweep
    if features.distinct_endpoints >= 3 or features.requests_per_sec > 2.5:
        return 1

    return 1



_last_broadcasts: Dict[Tuple, float] = {}

async def broadcast_event(event: DefenseEvent):
    now = time.time()
    atlas_id, asi_id = get_stage_tags(event.stage)
    event.atlas_id = atlas_id
    event.asi_id = asi_id

    action = event.verdict.action if event.verdict else event.event_type
    dedup_key = (event.event_type, event.stage, event.source_ip, action)

    # Suppress duplicate identical events within 120ms window (e.g. 12 concurrent recon hits)
    if dedup_key in _last_broadcasts and (now - _last_broadcasts[dedup_key]) < 0.120:
        return
    _last_broadcasts[dedup_key] = now

    _recent_defense_events.append(json.loads(event.model_dump_json()))
    if len(_recent_defense_events) > 250:
        del _recent_defense_events[:-250]

    # Prune stale dedup entries periodically
    if len(_last_broadcasts) > 200:
        old_keys = [k for k, v in _last_broadcasts.items() if now - v > 5.0]
        for k in old_keys:
            _last_broadcasts.pop(k, None)

    evt_json = event.model_dump_json()
    disconnected = set()
    for client in list(connected_clients):
        try:
            await client.send_text(evt_json)
        except Exception:
            disconnected.add(client)
    for client in disconnected:
        if client in connected_clients:
            connected_clients.remove(client)

async def listen_redis_alerts():
    """Background listener for alerts published by target (e.g. Stage 4 TCP lateral flood)"""
    while True:
        try:
            pubsub = redis_client.pubsub()
            await pubsub.subscribe("aegis:alerts")
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        if not AEGIS_ENABLED:
                            continue
                        data = json.loads(message["data"])
                        source_ip = data.get("source_ip", "unknown")
                        stage = data.get("stage", 4)
                        features = await surveillance.extract_features(source_ip)
                        # High packets/sec detected by target
                        features.packets_per_sec = float(data.get("pps", 80.0))

                        matched, sig_id, _ = await healer.match_signature(stage=stage, features=features.model_dump())
                        healing_sigs = [{"matched": matched}] if matched else []
                        verdict = await council.deliberate(features, healing_sigs, stage_hint=stage)

                        await responder.quarantine(source_ip, stage=stage, confidence=verdict.weighted_confidence)
                        await responder.record_lateral_drop(source_ip, features.packets_per_sec, verdict.action)
                        await healer.store_signature(stage, features.model_dump(), verdict.verdict_ms)
                        if matched and sig_id:
                            await healer.record_second_detection(sig_id, verdict.verdict_ms)

                        if metrics:
                            await metrics.record(TrialMetrics(
                                trial_id="live_trial",
                                run_id="live_run",
                                mode="aegis_on",
                                stage=stage,
                                detection_latency_ms=verdict.verdict_ms,
                                verdict=verdict.action,
                                confidence=verdict.weighted_confidence,
                                action="quarantine",
                                attack_succeeded=False,
                                ts=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                            ))

                        # Broadcast detection and quarantine events for Stage 4
                        await broadcast_event(DefenseEvent(
                            event_type="detection",
                            stage=stage,
                            source_ip=source_ip,
                            verdict=verdict,
                            ts=time.time(),
                            detail={"features": features.model_dump()}
                        ))
                        await broadcast_event(DefenseEvent(
                            event_type="quarantine",
                            stage=stage,
                            source_ip=source_ip,
                            verdict=verdict,
                            ts=time.time(),
                            detail={"reason": "lateral_flood_detected", "features": features.model_dump()}
                        ))
                    except Exception as e:
                        pass
        except Exception:
            await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, surveillance, council, responder, healer, metrics, http_client
    
    redis_client = redis.Redis(host='redis', port=6379, db=0)
    
    surveillance = SurveillanceLayer(redis_client)
    council = Council()
    responder = ResponseEngine(redis_client)
    healer = HealingEngine(redis_client, "/data/aegis.db")
    metrics = MetricsDB("/data/aegis.db")
    http_client = httpx.AsyncClient()
    
    await healer.init_db()
    await metrics.init_db()

    # Start background alert listener
    alert_task = asyncio.create_task(listen_redis_alerts())
    
    yield
    
    alert_task.cancel()
    try:
        await alert_task
    except asyncio.CancelledError:
        pass

    await http_client.aclose()
    await redis_client.aclose()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def aegis_middleware(request: Request, call_next):
    if (
        request.url.path.startswith("/api/aegis")
        or request.url.path.startswith("/api/reposcan")
        or request.url.path.startswith("/ws/")
    ):
        return await call_next(request)
        
    source_ip = request.headers.get("X-Real-IP", request.client.host)
    ts = time.time()
    
    if not AEGIS_ENABLED:
        req_url = f"{TARGET_URL}{request.url.path}"
        if request.url.query:
            req_url += f"?{request.url.query}"
        
        req_body = await request.body()
        resp = await http_client.request(
            method=request.method,
            url=req_url,
            headers=request.headers.raw,
            content=req_body
        )
        return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))

    headers = dict(request.headers)
    await surveillance.record_request(source_ip, request.url.path, request.headers.get("content-type", ""), headers, ts)

    features = await surveillance.extract_features(source_ip)
    stage = infer_stage_from_traffic(request.method, request.url.path, headers, features)


    matched, sig_id, _ = await healer.match_signature(stage=stage, features=features.model_dump())
    healing_sigs = [{"matched": matched}] if matched else []
    verdict = await council.deliberate(features, healing_sigs, stage_hint=stage)

    # Always broadcast detection event
    await broadcast_event(DefenseEvent(
        event_type="detection",
        stage=stage,
        source_ip=source_ip,
        verdict=verdict,
        ts=ts,
        detail={"features": features.model_dump()}
    ))

    # Check if already quarantined
    if await responder.is_blocked(source_ip):
        await broadcast_event(DefenseEvent(
            event_type="block",
            stage=stage,
            source_ip=source_ip,
            verdict=verdict,
            ts=ts,
            detail={"reason": "already_quarantined", "features": features.model_dump()}
        ))
        return await responder.black_hole_response()
        
    if verdict.action in ("quarantine", "block"):
        await responder.quarantine(source_ip, stage=stage, confidence=verdict.weighted_confidence)
        esc_item = escalation_mgr.enqueue_if_high_impact(
            source_ip=source_ip,
            stage=stage,
            confidence=verdict.weighted_confidence,
            proposed_action="subnet_quarantine" if stage in (4, 5, 6, 8, 9) else verdict.action,
        )
        if esc_item:
            await broadcast_raw_ws({"event_type": "escalation.queued", "escalation": esc_item.model_dump()})
        # Store signature in self-healing database non-blockingly
        async def _record_defense_bg():
            try:
                await healer.store_signature(stage, features.model_dump(), verdict.verdict_ms)
                if matched and sig_id:
                    await healer.record_second_detection(sig_id, verdict.verdict_ms)
                if metrics:
                    await metrics.record(TrialMetrics(
                        trial_id="live_trial",
                        run_id="live_run",
                        mode="aegis_on",
                        stage=stage,
                        detection_latency_ms=verdict.verdict_ms,
                        verdict=verdict.action,
                        confidence=verdict.weighted_confidence,
                        action=verdict.action,
                        attack_succeeded=False,
                        ts=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                    ))
            except Exception:
                pass
        asyncio.create_task(_record_defense_bg())

        await broadcast_event(DefenseEvent(
            event_type=verdict.action,
            stage=stage,
            source_ip=source_ip,
            verdict=verdict,
            ts=time.time(),
            detail={"features": features.model_dump()}
        ))
        return await responder.black_hole_response()

        
    if verdict.action == "ratelimit":
        esc_item = escalation_mgr.enqueue_if_needed(
            source_ip=source_ip,
            stage=stage,
            confidence=verdict.weighted_confidence,
            proposed_action=escalation_mgr.pending_policy,
        )
        if esc_item:
            await broadcast_raw_ws({"event_type": "escalation.queued", "escalation": esc_item.model_dump()})

        # Store signature for rate-limited / grey-zone behavior
        await healer.store_signature(stage, features.model_dump(), verdict.verdict_ms)

        if escalation_mgr.pending_policy == "provisional_block":
            await responder.quarantine(source_ip, stage=stage, confidence=verdict.weighted_confidence)
            await broadcast_event(DefenseEvent(
                event_type="block",
                stage=stage,
                source_ip=source_ip,
                verdict=verdict,
                ts=time.time(),
                detail={"reason": "provisional_block_grey_zone", "features": features.model_dump()}
            ))
            return await responder.black_hole_response()
        elif escalation_mgr.pending_policy == "provisional_ratelimit":
            allowed = await responder.ratelimit(source_ip)
            if not allowed:
                await broadcast_event(DefenseEvent(
                    event_type="ratelimit",
                    stage=stage,
                    source_ip=source_ip,
                    verdict=verdict,
                    ts=time.time(),
                    detail={"reason": "token_exhausted", "features": features.model_dump()}
                ))
                return Response(status_code=429, content=json.dumps({"error": "ratelimit"}), media_type="application/json")

    await broadcast_event(DefenseEvent(
        event_type="allow",
        stage=stage,
        source_ip=source_ip,
        verdict=verdict,
        ts=time.time(),
        detail={}
    ))
    
    req_url = f"{TARGET_URL}{request.url.path}"
    if request.url.query:
        req_url += f"?{request.url.query}"
        
    req_body = await request.body()
    resp = await http_client.request(
        method=request.method,
        url=req_url,
        headers=request.headers.raw,
        content=req_body
    )
    return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))

@app.get("/api/aegis/status")
async def get_status():
    blocklist = await responder.get_blocklist()
    stats = await healer.get_healing_stats()
    return {
        "enabled": AEGIS_ENABLED,
        "blocklist_count": len(blocklist),
        "signatures_stored": stats["signatures_stored"],
        "uptime": "ACTIVE"
    }

@app.post("/api/aegis/toggle")
async def toggle_aegis(request: Request):
    global AEGIS_ENABLED
    data = await request.json()
    if "enabled" in data:
        AEGIS_ENABLED = bool(data["enabled"])
    return {"enabled": AEGIS_ENABLED}

@app.get("/api/aegis/blocklist")
async def get_blocklist():
    return await responder.get_blocklist()

@app.get("/api/aegis/lateral-status")
async def get_lateral_status(source_ip: str = None):
    return await responder.get_lateral_drop(source_ip)

@app.get("/api/aegis/healing-stats")
async def get_healing_stats():
    return await healer.get_healing_stats()

@app.get("/api/aegis/metrics")
async def get_metrics(trial_id: str = "default"):
    return await metrics.get_trial_summary(trial_id)

@app.post("/api/aegis/reset")
async def reset_aegis():
    keys = await redis_client.keys("aegis:*")
    if keys:
        await redis_client.delete(*keys)
    escalation_mgr.clear()
    _recent_defense_events.clear()
    return {"status": "reset"}


@app.get("/api/aegis/escalations")
async def get_escalations():
    return escalation_mgr.list_items()


@app.get("/api/aegis/events")
async def get_recent_events():
    return _recent_defense_events


@app.post("/api/aegis/escalations/{escalation_id}")
async def resolve_escalation(escalation_id: str, request: Request):
    data = await request.json()
    decision = str(data.get("decision", "approve"))
    item = escalation_mgr.resolve(escalation_id, decision)
    if not item:
        return Response(content=json.dumps({"error": "Escalation not found"}), status_code=404, media_type="application/json")
    await broadcast_raw_ws({"event_type": "escalation.resolved", "escalation": item.model_dump()})
    return item.model_dump()


@app.get("/api/aegis/incident/{run_id}.md")
async def export_incident_markdown(run_id: str):
    sigs = await healer.get_signatures() if healer else []
    bl = await responder.get_blocklist() if responder else []
    md = generate_incident_markdown(run_id, _recent_defense_events, sigs, bl)
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="aegis_incident_{run_id}.md"'},
    )


@app.get("/api/aegis/incident/{run_id}.pdf")
async def export_incident_pdf(run_id: str):
    sigs = await healer.get_signatures() if healer else []
    bl = await responder.get_blocklist() if responder else []
    md = generate_incident_markdown(run_id, _recent_defense_events, sigs, bl)
    pdf_bytes = generate_incident_pdf(f"AEGIS Incident Report - {run_id}", md)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="aegis_incident_{run_id}.pdf"'},
    )

async def broadcast_raw_ws(payload: dict):
    msg = json.dumps(payload)
    disconnected = set()
    for client in list(connected_clients):
        try:
            await client.send_text(msg)
        except Exception:
            disconnected.add(client)
    for client in disconnected:
        connected_clients.discard(client)


def map_findings_to_stages(findings: list) -> list[int]:
    """Map RepoScan findings to JadePuffer-sim stages (including optional AI stages)."""
    stages = {1}  # Always start with RECON
    for f in findings:
        cid = f.get("check_id", "") if isinstance(f, dict) else getattr(f, "check_id", "")
        if cid in ("A2", "A3", "C1", "C2", "C5"):
            stages.add(3)  # Stage 03 AILM
        if cid in ("C3",):
            stages.add(6)  # Stage 06 MCP tool poisoning
        if cid in ("C7",):
            stages.add(7)  # Stage 07 RAG indirect prompt injection
        if cid in ("B2", "B3", "A6"):
            stages.add(8)  # Stage 08 Slopsquat / Supply-chain stage
        if cid in ("C8", "A8"):
            stages.add(9)  # Stage 09 Credential harvest
        if cid in ("A1", "B1", "C4", "C6"):
            stages.add(5)  # Stage 05 EXEC
        if cid in ("A4", "A5", "A7"):
            stages.add(4)  # Stage 04 LATERAL
    if len(stages) < 3:
        stages.update({2, 3, 5})
    return sorted(stages)


async def ingest_reposcan_signatures(report_dict: dict):
    """Store RepoScan findings as signatures in the Self-Healing Loop and teach SurveillanceLayer."""
    findings = report_dict.get("findings", [])
    for f in findings:
        cid = f.get("check_id", "")
        ev = f.get("evidence", "")
        if cid in ("C1", "C2", "A2", "A3") and surveillance:
            if "ignore previous" in ev.lower():
                surveillance.add_learned_pattern("ignore previous")
            if "u+200b" in ev.lower():
                surveillance.add_learned_pattern("\u200b")
        if healer:
            stage_mapped = 3 if cid.startswith("C") or cid in ("A2", "A3") else (5 if cid in ("B1", "A1") else 2)
            synthetic_features = {
                "distinct_endpoints": 4 if stage_mapped == 1 else 1,
                "injection_regex_hits": 1 if stage_mapped == 3 else 0,
                "packets_per_sec": 0.0,
                "content_type_sequence": ["application/json"],
                "reposcan_check_id": cid,
            }
            await healer.store_signature(stage_mapped, synthetic_features, 8.5)


@app.post("/api/reposcan")
async def api_start_reposcan(request: Request):
    body = await request.json()
    url = str(body.get("url", "")).strip()
    ref = body.get("ref")

    await broadcast_raw_ws({"event_type": "reposcan.progress", "phase": "validating_and_cloning", "pct": 15, "url": url})

    report_dict = None
    # Try calling dedicated reposcan container first
    try:
        resp = await http_client.post(
            f"{REPOSCAN_URL}/api/reposcan",
            json={"url": url, "ref": ref, "force_rescan": bool(body.get("force_rescan", False))},
            timeout=125.0,
        )
        if resp.status_code >= 400:
            detail = resp.json().get("detail", "RepoScan failed")
            return Response(content=json.dumps({"error": detail}), status_code=resp.status_code, media_type="application/json")
        data = resp.json()
        report_dict = data.get("report") or data
    except Exception:
        # Local fallback if running outside Docker compose or reposcan container is building
        import sys
        from pathlib import Path
        for candidate in (Path("/app/reposcan_local"), Path(__file__).resolve().parents[1] / "reposcan"):
            if candidate.exists() and str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
        try:
            from engine import RepoScannerEngine
            from cloner import validate_github_url
            norm_url, owner, repo = validate_github_url(url)
            local_engine = RepoScannerEngine(db_path="/data/reposcan.db")
            fixtures_dir = Path(os.getenv("REPOSCAN_FIXTURES_ROOT", "/app/fixtures"))
            if not fixtures_dir.exists():
                fixtures_dir = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
            loop = asyncio.get_running_loop()
            if owner == "aegis-demo" and (fixtures_dir / repo).exists():
                rep_obj = await loop.run_in_executor(None, local_engine.scan_local_directory, fixtures_dir / repo, norm_url, None, None)
            else:
                rep_obj = await loop.run_in_executor(None, local_engine.scan_github_url, norm_url, ref, None, None)
            report_dict = json.loads(rep_obj.model_dump_json())
        except ValueError as ve:
            return Response(content=json.dumps({"error": str(ve)}), status_code=400, media_type="application/json")
        except Exception as exc:
            return Response(content=json.dumps({"error": str(exc)}), status_code=422, media_type="application/json")

    scan_id = report_dict["scan_id"]
    _reposcan_cache[scan_id] = report_dict

    # Stream findings & completion over WebSocket
    for f in report_dict.get("findings", []):
        await broadcast_raw_ws({"event_type": "reposcan.finding", "scan_id": scan_id, "finding": f})

    await ingest_reposcan_signatures(report_dict)

    await broadcast_raw_ws({
        "event_type": "reposcan.done",
        "scan_id": scan_id,
        "proneness_pct": report_dict.get("proneness_pct"),
        "risk_band": report_dict.get("risk_band"),
    })
    return {"scan_id": scan_id, "report": report_dict}


@app.get("/api/reposcan/{scan_id}")
async def api_get_reposcan(scan_id: str):
    if scan_id in _reposcan_cache:
        return _reposcan_cache[scan_id]
    try:
        resp = await http_client.get(f"{REPOSCAN_URL}/api/reposcan/{scan_id}", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            _reposcan_cache[scan_id] = data
            return data
    except Exception:
        pass
    return Response(content=json.dumps({"error": "Scan not found"}), status_code=404, media_type="application/json")


@app.get("/api/reposcan/{scan_id}/report.md")
async def api_get_reposcan_md(scan_id: str):
    try:
        resp = await http_client.get(f"{REPOSCAN_URL}/api/reposcan/{scan_id}/report.md", timeout=10.0)
        if resp.status_code == 200:
            return Response(
                content=resp.content,
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="reposcan_{scan_id}.md"'},
            )
    except Exception:
        pass
    if scan_id in _reposcan_cache:
        import sys
        from pathlib import Path
        for candidate in (Path("/app/reposcan_local"), Path(__file__).resolve().parents[1] / "reposcan"):
            if candidate.exists() and str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
        from models import RepoScanReport
        from report_export import render_markdown_report
        rep = RepoScanReport.model_validate(_reposcan_cache[scan_id])
        md = render_markdown_report(rep)
        return Response(
            content=md,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="reposcan_{scan_id}.md"'},
        )
    return Response(content="Not found", status_code=404)


@app.get("/api/reposcan/{scan_id}/report.pdf")
async def api_get_reposcan_pdf(scan_id: str):
    try:
        resp = await http_client.get(f"{REPOSCAN_URL}/api/reposcan/{scan_id}/report.pdf", timeout=10.0)
        if resp.status_code == 200:
            return Response(
                content=resp.content,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="reposcan_{scan_id}.pdf"'},
            )
    except Exception:
        pass
    if scan_id in _reposcan_cache:
        import sys
        from pathlib import Path
        for candidate in (Path("/app/reposcan_local"), Path(__file__).resolve().parents[1] / "reposcan"):
            if candidate.exists() and str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
        from models import RepoScanReport
        from report_export import render_markdown_report, render_pdf_bytes
        rep = RepoScanReport.model_validate(_reposcan_cache[scan_id])
        md = render_markdown_report(rep)
        pdf_bytes = render_pdf_bytes(f"AEGIS RepoScan Report - {rep.repo_owner}/{rep.repo_name}", md)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="reposcan_{scan_id}.pdf"'},
        )
    return Response(content="Not found", status_code=404)


@app.post("/api/reposcan/{scan_id}/simulate")
async def api_simulate_reposcan_against_aegis(scan_id: str):
    """
    Map RepoScan findings to JadePuffer-sim stages and trigger a sandboxed attack run
    against the toy target ONLY (never against the scanned repository).
    """
    report_dict = _reposcan_cache.get(scan_id)
    if not report_dict:
        try:
            resp = await http_client.get(f"{REPOSCAN_URL}/api/reposcan/{scan_id}", timeout=10.0)
            if resp.status_code == 200:
                report_dict = resp.json()
        except Exception:
            pass
    if not report_dict:
        return Response(content=json.dumps({"error": "Scan not found"}), status_code=404, media_type="application/json")

    stages_to_run = map_findings_to_stages(report_dict.get("findings", []))
    # Clear existing blocklist so the simulation cleanly demonstrates stage interception
    keys = await redis_client.keys("aegis:blocklist:*")
    if keys:
        await redis_client.delete(*keys)

    try:
        r = await http_client.post(
            f"{ATTACKER_URL}/api/run",
            json={
                "use_proxy": True,
                "speed_multiplier": 1.5,
                "mutation_seed": 42,
                "stages": stages_to_run,
                "mode": "once",
            },
            timeout=10.0,
        )
        run_info = r.json() if r.status_code < 400 else {"status": "triggered"}
    except Exception as exc:
        run_info = {"status": "local_simulated", "detail": str(exc)}

    return {
        "scan_id": scan_id,
        "target": "aegis_toy_target_only",
        "mapped_stages": stages_to_run,
        "attacker_run": run_info,
    }


@app.websocket("/ws/defense")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
