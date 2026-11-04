import redis.asyncio as redis
from fastapi import Response
import time

class ResponseEngine:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        
    async def quarantine(self, source_ip: str, ttl: int = 60, stage: int = 1, confidence: float = 0.90):
        key = f"aegis:blocklist:{source_ip}"
        meta_key = f"aegis:blockmeta:{source_ip}"
        import json
        await self.redis.set(key, "quarantined", ex=ttl)
        await self.redis.set(meta_key, json.dumps({
            "ip": source_ip,
            "action": "quarantine",
            "stage": stage,
            "confidence": round(confidence, 3),
            "ts": time.time(),
        }), ex=ttl)
        
    async def record_lateral_drop(self, source_ip: str, pps: float, verdict_action: str = "quarantine", ttl: int = 60):
        import json
        drop_key = f"aegis:lateral_drop:{source_ip}"
        await self.redis.set(drop_key, json.dumps({
            "dropped": True,
            "action": "token_bucket_drop",
            "verdict": verdict_action,
            "source_ip": source_ip,
            "pps": round(pps, 1),
            "ts": time.time(),
        }), ex=ttl)

    async def get_lateral_drop(self, source_ip: str = None) -> dict:
        import json
        if source_ip:
            raw = await self.redis.get(f"aegis:lateral_drop:{source_ip}")
            if raw:
                return json.loads(raw)
        # Fallback: check any active lateral drop in window
        keys = await self.redis.keys("aegis:lateral_drop:*")
        if keys:
            raw = await self.redis.get(keys[0])
            if raw:
                return json.loads(raw)
        return {"dropped": False}

    async def is_blocked(self, source_ip: str) -> bool:
        key = f"aegis:blocklist:{source_ip}"
        return await self.redis.exists(key) > 0
        
    async def ratelimit(self, source_ip: str) -> bool:
        key = f"aegis:ratelimit:{source_ip}"
        current = await self.redis.get(key)
        if current is None:
            await self.redis.set(key, 9, ex=1)  # 10 tokens - 1 used
            return True
            
        current_val = int(current)
        if current_val > 0:
            await self.redis.decr(key)
            return True
        return False
        
    async def get_blocklist(self) -> list:
        import json
        keys = await self.redis.keys("aegis:blocklist:*")
        blocklist = []
        for key in keys:
            if isinstance(key, bytes):
                key = key.decode('utf-8')
            ip = key.split(":")[-1]
            ttl = await self.redis.ttl(key)
            meta_raw = await self.redis.get(f"aegis:blockmeta:{ip}")
            meta = json.loads(meta_raw) if meta_raw else {}
            blocklist.append({
                "ip": ip,
                "action": meta.get("action", "quarantine"),
                "stage": meta.get("stage", 1),
                "confidence": meta.get("confidence", 0.90),
                "expires_at": time.time() + ttl if ttl > 0 else 0
            })
        return blocklist
        
    async def black_hole_response(self) -> Response:
        import json
        return Response(
            content=json.dumps({"error": "connection_refused", "code": "AEGIS_QUARANTINE"}),
            status_code=403,
            media_type="application/json"
        )
