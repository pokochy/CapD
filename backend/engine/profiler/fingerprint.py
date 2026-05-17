"""
engine/profiler/fingerprint.py
───────────────────────────────
1단계: 대상 서버의 기술 스택과 WAF 존재 여부를 HTTP 헤더·응답으로 탐지.
"""

from __future__ import annotations

import re

from utils.http_client import HttpClient
from utils.logger import get_logger

logger = get_logger("profiler")

# 서버 기술 스택 지문
_SERVER_SIGNATURES: dict[str, list[str]] = {
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["microsoft-iis", "asp.net"],
    "express": ["express"],
    "flask": ["werkzeug"],
    "django": ["csrfmiddlewaretoken", "django"],
    "spring": ["spring", "x-application-context"],
    "rails": ["x-powered-by: phusion passenger", "set-cookie: _session_id"],
    "laravel": ["laravel_session"],
    "wordpress": ["wp-content", "wp-includes"],
}

# WAF 지문
_WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cloudflare"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-check-cacheable"],
    "Sucuri": ["x-sucuri-id"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP": ["bigipserver", "f5"],
}


class Fingerprinter:
    """대상 URL의 기술 스택 및 WAF를 탐지."""

    async def run(self, url: str) -> dict:
        """
        반환:
          {
            "server": str | None,
            "technologies": [str],
            "waf": str | None,
            "waf_detected": bool,
            "response_time_ms": float,
          }
        """
        logger.info(f"[Profiler] Fingerprinting: {url}")

        async with HttpClient() as client:
            import time
            t0 = time.monotonic()
            resp = await client.get(url)
            elapsed = (time.monotonic() - t0) * 1000

        headers_raw = " ".join(
            f"{k}: {v}" for k, v in resp.get("headers", {}).items()
        ).lower()
        body_snippet = resp.get("body", "")[:3000].lower()
        combined = headers_raw + " " + body_snippet

        technologies = self._detect_technologies(combined)
        waf, waf_detected = self._detect_waf(combined)
        server = resp.get("headers", {}).get("Server") or resp.get("headers", {}).get("server")

        result = {
            "server": server,
            "technologies": technologies,
            "waf": waf,
            "waf_detected": waf_detected,
            "response_time_ms": round(elapsed, 2),
            "status_code": resp.get("status"),
        }
        logger.info(f"[Profiler] Result: tech={technologies}, waf={waf}")
        return result

    def _detect_technologies(self, text: str) -> list[str]:
        detected: list[str] = []
        for tech, sigs in _SERVER_SIGNATURES.items():
            if any(sig in text for sig in sigs):
                detected.append(tech)
        return detected

    def _detect_waf(self, text: str) -> tuple[str | None, bool]:
        for waf_name, sigs in _WAF_SIGNATURES.items():
            if any(sig.lower() in text for sig in sigs):
                return waf_name, True
        return None, False
