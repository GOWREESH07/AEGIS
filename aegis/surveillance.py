import time
import re
from typing import List, Dict, Any
import redis.asyncio as redis
from models import TrafficFeatures

class SurveillanceLayer:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.injection_pattern = re.compile(
            r'ignore previous|system prompt|jailbreak|<script|UNION SELECT|DROP TABLE|eval\(|base64_decode|__import__|payload_execution|exec_payload|lock_staging|mcp_tool_registration|rag_document_ingest|slopsquat_install|cred_harvest|~\/\.claude|~\/\.gemini|\.env|\u200b|\u200c|\u200d|\u2060|\ufeff|[\u202a-\u202e]|[\u2066-\u2069]',
            re.IGNORECASE
        )
        self.learned_patterns: List[str] = []

        self.window = 5

    def add_learned_pattern(self, token: str):
        if token and token not in self.learned_patterns:
            self.learned_patterns.append(token.lower())

    async def record_request(self, source_ip: str, path: str, content_type: str, headers: Dict[str, str], ts: float):
        req_key = f"aegis:req:{source_ip}"
        import json
        
        is_injection = 0
        for k, v in headers.items():
            if self.injection_pattern.search(v):
                is_injection = 1
                break
            v_low = v.lower()
            if any(lp in v_low for lp in self.learned_patterns):
                is_injection = 1
                break
        
        data = {
            'path': path,
            'content_type': content_type,
            'injection': is_injection,
            'ts': ts
        }
        
        pipe = self.redis.pipeline(transaction=False)
        pipe.zadd(req_key, {json.dumps(data): ts})
        pipe.zremrangebyscore(req_key, 0, ts - 10)
        pipe.expire(req_key, 20)
        await pipe.execute()

    async def extract_features(self, source_ip: str) -> TrafficFeatures:
        now = time.time()
        req_key = f"aegis:req:{source_ip}"
        pps_key = f"aegis:pps:{source_ip}"
        
        pipe = self.redis.pipeline(transaction=False)
        pipe.zrangebyscore(req_key, now - 5, now)
        pipe.zrangebyscore(req_key, now - 10, now)
        pipe.get(pps_key)
        reqs_5s, reqs_10s, pps_val = await pipe.execute()
        
        import json
        reqs_5s_parsed = [json.loads(r) for r in reqs_5s]
        reqs_10s_parsed = [json.loads(r) for r in reqs_10s]
        
        requests_per_sec = len(reqs_5s_parsed) / 5.0
        distinct_endpoints = len(set(r.get('path') for r in reqs_5s_parsed))
        
        content_type_sequence = [r.get('content_type') for r in reqs_10s_parsed if r.get('content_type')]
        if len(content_type_sequence) > 10:
            content_type_sequence = content_type_sequence[-10:]
            
        injection_regex_hits = sum(1 for r in reqs_5s_parsed if r.get('injection', 0) == 1)
        
        packets_per_sec = float(pps_val) if pps_val else 0.0
        
        return TrafficFeatures(
            source_ip=source_ip,
            timestamp=now,
            requests_per_sec=requests_per_sec,
            distinct_endpoints=distinct_endpoints,
            content_type_sequence=content_type_sequence,
            injection_regex_hits=injection_regex_hits,
            packets_per_sec=packets_per_sec,
            window_seconds=5
        )
