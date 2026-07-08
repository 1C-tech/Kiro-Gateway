# -*- coding: utf-8 -*-
"""
Console / statistics collector for Kiro Gateway.

Singleton that accumulates request logs and time-bucketed stats
for the admin console dashboard.
"""

from collections import deque
from datetime import datetime, timedelta


class StatsCollector:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if StatsCollector._initialized:
            return
        StatsCollector._initialized = True

        self.request_logs = deque(maxlen=500)
        self.hourly_buckets = {}  # "2026-07-08T14" -> dict

    def record_request(
        self,
        account_id: str,
        model: str,
        status: str,
        status_code: int,
        client_ip: str = "",
        method: str = "",
        url: str = "",
        request_body: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        duration: float = 0.0,
    ):
        now = datetime.now()

        log_entry = {
            "time": now.strftime("%H:%M:%S"),
            "timestamp": now.isoformat(),
            "account_id": account_id,
            "model": model,
            "status": status,
            "status_code": status_code,
            "client_ip": client_ip,
            "method": method,
            "url": url,
            "request_body": self._truncate_body(request_body),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "duration": round(duration, 2),
        }
        self.request_logs.appendleft(log_entry)

        bucket_key = now.strftime("%Y-%m-%dT%H")
        if bucket_key not in self.hourly_buckets:
            self.hourly_buckets[bucket_key] = {
                "input_tokens": 0,
                "output_tokens": 0,
                "requests": 0,
                "success": 0,
                "failed": 0,
            }
        bucket = self.hourly_buckets[bucket_key]
        bucket["input_tokens"] += input_tokens
        bucket["output_tokens"] += output_tokens
        bucket["requests"] += 1
        if status == "success":
            bucket["success"] += 1
        else:
            bucket["failed"] += 1

    def _truncate_body(self, body: str, max_len: int = 600) -> str:
        if not body:
            return ""
        if len(body) <= max_len:
            return body
        return body[:max_len] + "..."

    def get_logs(self, limit: int = 100) -> list:
        return list(self.request_logs)[:limit]

    def get_stats(self, scale: str = "day") -> dict:
        now = datetime.now()
        buckets = list(self.hourly_buckets.items())

        if scale == "day":
            result = []
            for h in range(24):
                t = now.replace(minute=0, second=0, microsecond=0)
                t = t - timedelta(hours=23 - h)
                key = t.strftime("%Y-%m-%dT%H")
                data = self.hourly_buckets.get(
                    key,
                    {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "requests": 0,
                        "success": 0,
                        "failed": 0,
                    },
                )
                result.append({"time": t.strftime("%H:00"), "timestamp": key, **data})

        elif scale == "week":
            result = []
            for d in range(7):
                day = now - timedelta(days=6 - d)
                day_key = day.strftime("%Y-%m-%d")
                agg = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "requests": 0,
                    "success": 0,
                    "failed": 0,
                }
                for hk, hv in buckets:
                    if hk.startswith(day_key):
                        for k in agg:
                            agg[k] += hv[k]
                result.append({"time": day.strftime("%m/%d"), "timestamp": day_key, **agg})

        elif scale == "month":
            result = []
            for d in range(30):
                day = now - timedelta(days=29 - d)
                day_key = day.strftime("%Y-%m-%d")
                agg = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "requests": 0,
                    "success": 0,
                    "failed": 0,
                }
                for hk, hv in buckets:
                    if hk.startswith(day_key):
                        for k in agg:
                            agg[k] += hv[k]
                result.append({"time": day.strftime("%m/%d"), "timestamp": day_key, **agg})
        else:
            return {"series": [], "totals": {}}

        totals = {
            "input_tokens": 0,
            "output_tokens": 0,
            "requests": 0,
            "success": 0,
            "failed": 0,
        }
        for _, hv in buckets:
            for k in totals:
                totals[k] += hv[k]
        totals["success_rate"] = round(
            totals["success"] / max(totals["requests"], 1) * 100, 1
        )

        return {"series": result, "totals": totals}
