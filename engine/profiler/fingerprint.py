"""
engine/profiler/fingerprint.py
───────────────────────────────
1단계: 대상 서버의 기술 스택과 WAF 존재 여부를 HTTP 헤더·응답으로 탐지.

cli/fingerprinter.py 통합:
  - OS, 언어, 프레임워크, 보안 헤더 누락 탐지
  - 알려진 취약 버전 검증
  - print_fingerprint()로 컬러 출력 지원 (CLI 모드)
"""

from __future__ import annotations

import re
import time as _time

from utils.http_client import HttpClient
from utils.logger import get_logger

logger = get_logger("profiler")

# ── 서버 기술 스택 지문 (WAF·서버 탐지용) ─────────────────────────────────────
_SERVER_SIGNATURES: dict[str, list[str]] = {
    "nginx":     ["nginx"],
    "apache":    ["apache"],
    "iis":       ["microsoft-iis", "asp.net"],
    "express":   ["express"],
    "flask":     ["werkzeug"],
    "django":    ["csrfmiddlewaretoken", "django"],
    "spring":    ["spring", "x-application-context"],
    "rails":     ["x-powered-by: phusion passenger", "set-cookie: _session_id"],
    "laravel":   ["laravel_session"],
    "wordpress": ["wp-content", "wp-includes"],
}

# ── WAF 지문 ─────────────────────────────────────────────────────────────────
_WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":  ["cf-ray", "cloudflare"],
    "AWS WAF":     ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai":      ["akamai", "x-check-cacheable"],
    "Sucuri":      ["x-sucuri-id"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP":   ["bigipserver", "f5"],
}

# ── 상세 핑거프린팅 시그니처 (CLI 통합) ──────────────────────────────────────
_DETAILED_SIGNATURES: dict = {
    "webserver": {
        "Apache":    {"header": "server",       "pattern": r"Apache/([\d.]+)"},
        "Nginx":     {"header": "server",       "pattern": r"[Nn]ginx/([\d.]+)"},
        "IIS":       {"header": "server",       "pattern": r"Microsoft-IIS/([\d.]+)"},
        "LiteSpeed": {"header": "server",       "pattern": r"LiteSpeed"},
    },
    "os": {
        "Ubuntu":  {"header": "server", "pattern": r"Ubuntu"},
        "Debian":  {"header": "server", "pattern": r"Debian"},
        "CentOS":  {"header": "server", "pattern": r"CentOS"},
        "Windows": {"header": "server", "pattern": r"Win(dows|32|64)"},
    },
    "language": {
        "PHP":     {"header": "x-powered-by", "pattern": r"PHP/([\d.]+)"},
        "ASP.NET": {"header": "x-powered-by", "pattern": r"ASP\.NET"},
        "Python":  {"header": "x-powered-by", "pattern": r"Python|Django|Flask"},
        "Ruby":    {"header": "x-powered-by", "pattern": r"Phusion Passenger|Ruby"},
    },
    "framework": {
        "WordPress": {"body":   r"wp-content|wp-includes"},
        "Joomla":    {"body":   r"/components/com_|Joomla"},
        "Drupal":    {"body":   r"Drupal|drupal\.js"},
        "Laravel":   {"header": "set-cookie", "pattern": r"laravel_session"},
        "Django":    {"header": "set-cookie", "pattern": r"csrftoken"},
        "Express":   {"header": "x-powered-by", "pattern": r"Express"},
    },
    "security_headers": {
        "X-Frame-Options":           "x-frame-options",
        "X-XSS-Protection":          "x-xss-protection",
        "Content-Security-Policy":   "content-security-policy",
        "Strict-Transport-Security": "strict-transport-security",
        "X-Content-Type-Options":    "x-content-type-options",
    },
}

_VULNERABLE_VERSIONS: dict[str, list[str]] = {
    "Apache": ["2.4.49", "2.4.50", "2.2.0", "2.2.1"],
    "Nginx":  ["1.0.0", "1.0.1", "1.14.0"],
    "PHP":    ["5.6.0", "7.0.0", "7.1.0", "7.2.0"],
    "IIS":    ["6.0", "7.0"],
}


def _extract_version(value: str, pattern: str) -> str:
    m = re.search(pattern, value, re.I)
    return m.group(1) if m and m.lastindex else "unknown"


def _validate_version(tech: str, version: str) -> dict:
    if version == "unknown":
        return {"tech": tech, "version": version,
                "status": "unknown", "message": f"{tech}: 버전을 확인할 수 없습니다"}
    if tech in _VULNERABLE_VERSIONS and version in _VULNERABLE_VERSIONS[tech]:
        return {"tech": tech, "version": version,
                "status": "vulnerable", "message": f"{tech} {version} — 알려진 취약 버전 (CVE 등록됨)"}
    return {"tech": tech, "version": version,
            "status": "ok", "message": f"{tech} {version} — 알려진 치명적 취약점 없음"}


class Fingerprinter:
    """대상 URL의 기술 스택 및 WAF를 탐지."""

    async def run(self, url: str) -> dict:
        """
        반환값:
          server, technologies, waf, waf_detected, response_time_ms, status_code
          + webserver, webserver_version, os, language, language_version,
            framework, security_headers, missing_security, validation
        """
        logger.info(f"[Profiler] Fingerprinting: {url}")

        async with HttpClient() as client:
            t0 = _time.monotonic()
            resp = await client.get(url)
            elapsed = (_time.monotonic() - t0) * 1000

        headers_dict = resp.get("headers", {})
        headers_lower = {k.lower(): v for k, v in headers_dict.items()}
        headers_raw = " ".join(f"{k}: {v}" for k, v in headers_lower.items())
        body = resp.get("body", "")
        body_snippet = body[:3000].lower()
        combined = headers_raw.lower() + " " + body_snippet

        technologies = self._detect_technologies(combined)
        waf, waf_detected = self._detect_waf(combined)
        server = headers_dict.get("Server") or headers_dict.get("server")

        # ── 상세 탐지 ────────────────────────────────────────────────────────
        webserver, webserver_version = None, "unknown"
        for tech, sig in _DETAILED_SIGNATURES["webserver"].items():
            val = headers_lower.get(sig["header"], "")
            if re.search(sig["pattern"], val, re.I):
                webserver = tech
                webserver_version = _extract_version(val, sig["pattern"])
                break

        os_name = None
        for tech, sig in _DETAILED_SIGNATURES["os"].items():
            if re.search(sig["pattern"], headers_lower.get(sig["header"], ""), re.I):
                os_name = tech
                break

        language, language_version = None, "unknown"
        for tech, sig in _DETAILED_SIGNATURES["language"].items():
            val = headers_lower.get(sig.get("header", ""), "")
            if re.search(sig["pattern"], val, re.I):
                language = tech
                language_version = _extract_version(val, sig["pattern"])
                break

        framework: list[str] = []
        for tech, sig in _DETAILED_SIGNATURES["framework"].items():
            if "body" in sig:
                if re.search(sig["body"], body_snippet, re.I):
                    framework.append(tech)
            elif "header" in sig:
                val = headers_lower.get(sig["header"], "")
                if re.search(sig["pattern"], val, re.I):
                    framework.append(tech)

        security_headers, missing_security = [], []
        for name, key in _DETAILED_SIGNATURES["security_headers"].items():
            (security_headers if key in headers_lower else missing_security).append(name)

        validation = []
        for tech, version in [(webserver, webserver_version), (language, language_version)]:
            if tech:
                validation.append(_validate_version(tech, version))

        result = {
            "url":               url,
            "server":            server,
            "technologies":      technologies,
            "waf":               waf,
            "waf_detected":      waf_detected,
            "response_time_ms":  round(elapsed, 2),
            "status_code":       resp.get("status"),
            "webserver":         webserver,
            "webserver_version": webserver_version,
            "os":                os_name,
            "language":          language,
            "language_version":  language_version,
            "framework":         framework,
            "security_headers":  security_headers,
            "missing_security":  missing_security,
            "validation":        validation,
        }
        logger.info(f"[Profiler] Result: tech={technologies}, waf={waf}, "
                    f"server={webserver}, lang={language}")
        return result

    def _detect_technologies(self, text: str) -> list[str]:
        return [tech for tech, sigs in _SERVER_SIGNATURES.items()
                if any(sig in text for sig in sigs)]

    def _detect_waf(self, text: str) -> tuple[str | None, bool]:
        for waf_name, sigs in _WAF_SIGNATURES.items():
            if any(sig.lower() in text for sig in sigs):
                return waf_name, True
        return None, False


# ── CLI 컬러 출력 ─────────────────────────────────────────────────────────────
_R = "\033[91m"; _G = "\033[92m"; _Y = "\033[93m"
_C = "\033[96m"; _D = "\033[0m";  _B = "\033[1m"


def print_fingerprint(result: dict) -> None:
    """CLI 모드용 컬러 핑거프린트 출력."""
    print(f"\n{_B}{'='*55}{_D}")
    print(f"{_B}  대상: {result.get('url', '')}{_D}")
    print(f"{_B}{'='*55}{_D}")

    ws  = result.get("webserver") or result.get("server") or "unknown"
    wv  = result.get("webserver_version", "")
    os_ = result.get("os") or "unknown"
    lg  = result.get("language") or "unknown"
    lv  = result.get("language_version", "")
    fw  = ", ".join(result.get("framework", [])) or "감지되지 않음"
    waf = result.get("waf") or "없음"
    rtt = result.get("response_time_ms", 0)

    print(f"\n  {_C}[Web Server]{_D}  {ws} {wv}")
    print(f"  {_C}[OS]{_D}          {os_}")
    print(f"  {_C}[Language]{_D}    {lg} {lv}")
    print(f"  {_C}[Framework]{_D}   {fw}")
    print(f"  {_C}[WAF]{_D}         {waf}")
    print(f"  {_C}[응답시간]{_D}    {rtt}ms")

    if result.get("validation"):
        print(f"\n  {_B}--- 버전 검증 ---{_D}")
        for v in result["validation"]:
            icon, color = {"ok": ("PASS", _G), "vulnerable": ("FAIL", _R)}.get(
                v.get("status", ""), ("WARN", _Y)
            )
            print(f"  {color}[{icon}]{_D} {v.get('message', '')}")

    print(f"\n  {_B}--- 보안 헤더 ---{_D}")
    for h in result.get("security_headers", []):
        print(f"  {_G}[존재]{_D} {h}")
    for h in result.get("missing_security", []):
        print(f"  {_R}[누락]{_D} {h}")
    print()
