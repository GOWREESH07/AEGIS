import asyncio
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List

import redis.asyncio as redis
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = logging.getLogger("aegis.target")
logger.setLevel(logging.INFO)

SUSPICIOUS_REGEX = re.compile(
    r"ignore previous|system prompt|jailbreak|<script|UNION SELECT|DROP TABLE|eval\(|base64_decode|__import__",
    re.IGNORECASE,
)

redis_client = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        text = json.dumps(message)
        # Iterate over a copy of active connections
        for connection in list(self.active_connections):
            try:
                await connection.send_text(text)
            except Exception:
                try:
                    self.active_connections.remove(connection)
                except ValueError:
                    pass

manager = ConnectionManager()

# TCP server handler
async def handle_tcp_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info('peername')
    source_ip = addr[0] if addr else "unknown"

    # Check if source_ip is blocked in AEGIS blocklist
    if redis_client:
        try:
            is_blocked = await redis_client.exists(f"aegis:blocklist:{source_ip}")
            if is_blocked:
                # Notify AEGIS of blocked lateral movement
                await redis_client.publish(
                    "aegis:alerts",
                    json.dumps({"type": "lateral", "source_ip": source_ip, "action": "blocked", "stage": 4})
                )
                writer.close()
                await writer.wait_closed()
                return
        except Exception as e:
            logger.warning(f"Redis blocklist check error: {e}")

    packet_count = 0
    start_time = asyncio.get_event_loop().time()
    dropped_by_aegis = False

    while True:
        try:
            data = await reader.read(4096)
            if not data:
                break
            packet_count += max(1, len(data) // 64)

            # Mid-stream token-bucket rate limit & AEGIS alert at 50+ packets
            if redis_client and packet_count >= 50 and not dropped_by_aegis:
                elapsed_now = max(asyncio.get_event_loop().time() - start_time, 0.005)
                current_pps = packet_count / elapsed_now
                if current_pps > 15.0:
                    await redis_client.set(f"aegis:pps:{source_ip}", current_pps, ex=10)
                    await redis_client.publish(
                        "aegis:alerts",
                        json.dumps({
                            "type": "lateral",
                            "source_ip": source_ip,
                            "pps": current_pps,
                            "stage": 4,
                            "packet_count": packet_count,
                            "action": "token_bucket_drop"
                        })
                    )
                    # Check if AEGIS is enabled (not disabled) by checking or waiting briefly for drop confirmation
                    await asyncio.sleep(0.02)
                    if await redis_client.exists(f"aegis:blocklist:{source_ip}") or await redis_client.exists(f"aegis:lateral_drop:{source_ip}"):
                        dropped_by_aegis = True
                        break
        except Exception as e:
            logger.error(f"TCP connection error: {e}")
            break

    elapsed = max(asyncio.get_event_loop().time() - start_time, 0.005)
    pps = packet_count / elapsed

    if redis_client and packet_count > 0 and not dropped_by_aegis:
        try:
            await redis_client.set(f"aegis:pps:{source_ip}", pps, ex=10)
            await redis_client.publish(
                "aegis:alerts",
                json.dumps({
                    "type": "lateral",
                    "source_ip": source_ip,
                    "pps": pps,
                    "stage": 4,
                    "packet_count": packet_count
                })
            )
        except Exception as e:
            logger.warning(f"Redis report error: {e}")

    writer.close()
    await writer.wait_closed()


async def start_tcp_server():
    server = await asyncio.start_server(handle_tcp_connection, '0.0.0.0', 8002)
    logger.info("TCP server listening on 0.0.0.0:8002")
    async with server:
        await server.serve_forever()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    
    # Create staging dir and files
    os.makedirs("staging", exist_ok=True)
    for i in range(10):
        with open(f"staging/record_{i:02d}.txt", "w") as f:
            f.write("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
            
    # Connect to redis
    try:
        redis_client = redis.from_url("redis://redis:6379", decode_responses=True)
        await redis_client.ping()
        logger.info("Connected to Redis.")
    except Exception as e:
        logger.warning(f"Redis unavailable on startup: {e}")
        redis_client = None

    # Start TCP server
    tcp_task = asyncio.create_task(start_tcp_server())
    
    yield
    
    # Shutdown
    tcp_task.cancel()
    try:
        await tcp_task
    except asyncio.CancelledError:
        pass

    if redis_client:
        await redis_client.close()
        
    # Flush staging dir
    try:
        for i in range(10):
            try:
                os.remove(f"staging/record_{i:02d}.txt")
            except Exception:
                pass
        os.rmdir("staging")
    except Exception:
        pass


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_request_middleware(request: Request, call_next):
    # Log X-Forwarded-Context
    x_forwarded_context = request.headers.get("X-Forwarded-Context", "")
    injection_attempt = False
    if x_forwarded_context and SUSPICIOUS_REGEX.search(x_forwarded_context):
        injection_attempt = True
        logger.warning(f"Suspicious X-Forwarded-Context detected: {x_forwarded_context}")

    # Process request
    try:
        response = await call_next(request)
        status_code = response.status_code
    except Exception as e:
        logger.error(f"Internal error: {e}")
        status_code = 500
        response = JSONResponse(content={"error": "Internal server error"}, status_code=500)

    # Broadcast log entry
    client_ip = request.client.host if request.client else "unknown"
    content_type = request.headers.get("Content-Type")
    
    log_entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "path": request.url.path,
        "source_ip": client_ip,
        "content_type": content_type,
        "injection_flag": injection_attempt,
        "status_code": status_code
    }
    
    # Push to background to not block response
    asyncio.create_task(manager.broadcast(log_entry))
    
    return response

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# 12 Mock Endpoints
@app.get("/api/ping")
@app.post("/api/ping")
async def api_ping(): return {"status": "pong"}

@app.get("/api/status")
@app.post("/api/status")
async def api_status(): return {"status": "ok"}

@app.get("/api/auth")
@app.post("/api/auth")
async def api_auth(): return {"auth": "ok"}

@app.get("/api/users")
@app.post("/api/users")
async def api_users(): return {"users": []}

@app.get("/api/config")
@app.post("/api/config")
async def api_config(): return {"config": "loaded"}

@app.get("/api/data")
@app.post("/api/data")
async def api_data(): return {"data": "some_data"}

@app.get("/api/internal/health")
@app.post("/api/internal/health")
async def api_internal_health(): return {"health": "healthy"}

@app.get("/api/v2/scan")
@app.post("/api/v2/scan")
async def api_v2_scan(): return {"scan": "complete"}

@app.get("/api/metrics")
@app.post("/api/metrics")
async def api_metrics(): return {"metrics": "all"}

@app.get("/api/reports")
@app.post("/api/reports")
async def api_reports(): return {"reports": "generated"}

@app.get("/api/admin")
@app.post("/api/admin")
async def api_admin(): return {"admin": "ready"}

@app.api_route("/api/flow/execute", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def api_flow_execute(request: Request):
    content_type = request.headers.get("Content-Type", "")
    
    if request.method == "POST":
        body_bytes = await request.body()
        loop = asyncio.get_running_loop()
        if "application/xml" in content_type:
            try:
                root = await loop.run_in_executor(None, ET.fromstring, body_bytes)
                fields = len(root)
                return {"parsed": "xml", "fields": fields}
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": "invalid_xml", "details": str(e)})
        elif "application/json" in content_type:
            try:
                data = await loop.run_in_executor(None, json.loads, body_bytes)
                fields = len(data) if isinstance(data, dict) else len(data) if isinstance(data, list) else 1
                return {"parsed": "json", "fields": fields}
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": "invalid_json", "details": str(e)})
        else:
            return JSONResponse(
                status_code=400,
                content={"error": "unsupported_content_type", "received": content_type}
            )
    else:
        return {"message": "Use POST for payload processing"}

@app.post("/api/target/reset-staging")
@app.get("/api/target/reset-staging")
async def api_reset_staging():
    import pathlib
    p = pathlib.Path("staging")
    p.mkdir(parents=True, exist_ok=True)
    for f in p.glob("*.locked"):
        try:
            f.unlink()
        except Exception:
            pass
    for i in range(10):
        with open(p / f"record_{i:02d}.txt", "w") as f:
            f.write("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
    return {"status": "reset", "files_created": 10}


# ─────────────────────────────────────────────────────────────────────────────
# Feature 4: Optional AI-Attack Simulation Endpoints (Toy Target Only)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/mcp/register")
async def api_mcp_register(request: Request):
    """Toy MCP tool registration endpoint (receives simulated tool metadata)."""
    data = await request.json()
    return {
        "status": "registered",
        "tool_name": data.get("tool_name", "unknown_tool"),
        "description_len": len(str(data.get("description", ""))),
    }


@app.post("/api/rag/ingest")
async def api_rag_ingest(request: Request):
    """Toy RAG ingestion endpoint (stores simulated document text)."""
    data = await request.json()
    doc = str(data.get("document", ""))
    sanitized = request.headers.get("X-AEGIS-Sanitized", "false") == "true"
    return {
        "status": "ingested",
        "source": data.get("source", "external"),
        "sanitized_by_aegis": sanitized,
        "chars_stored": len(doc),
    }


@app.post("/api/packages/install")
async def api_packages_install(request: Request):
    """Toy package registry fetch simulator (never runs pip/npm)."""
    data = await request.json()
    return {
        "status": "simulated_fetch_ok",
        "ecosystem": data.get("ecosystem", "pypi"),
        "package": data.get("package", "unknown"),
    }


@app.post("/api/fs/read")
async def api_fs_read(request: Request):
    """Toy filesystem config reader (returns synthetic dummy string only)."""
    data = await request.json()
    path_req = str(data.get("path", ""))
    return {
        "status": "simulated_read",
        "path": path_req,
        "content_preview": "SIMULATED_DUMMY_CONFIG_DO_NOT_USE",
    }
