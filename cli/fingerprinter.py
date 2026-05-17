"""
fingerprinter.py — HTTP 헤더 기반 기술 스택 핑거프린팅
Scanner Pipeline Phase 0 에서 호출됨
"""
from __future__ import annotations

import re
import json
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ── 핑거프린팅 식별 기준표 ────────────────────────────────

SIGNATURES: dict = {
    "webserver": {
        "Apache":    {"header": "server",  "pattern": r"Apache/([\d.]+)"},
        "Nginx":     {"header": "server",  "pattern": r"[Nn]ginx/([\d.]+)"},
        "IIS":       {"header": "server",  "pattern": r"Microsoft-IIS/([\d.]+)"},
        "LiteSpeed": {"header": "server",  "pattern": r"LiteSpeed"},
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

VULNERABLE_VERSIONS: dict[str, list[str]] = {
    "Apache": ["2.4.49", "2.4.50", "2.2.0", "2.2.1"],
    "Nginx":  ["1.0.0",  "1.0.1",  "1.14.0"],
    "PHP":    ["5.6.0",  "7.0.0",  "7.1.0",  "7.2.0"],
    "IIS":    ["6.0",    "7.0"],
}


# ── 헬퍼 ────────────────────────────────────────────────

def _extract_version(value: str, pattern: str) -> str:
    m = re.search(pattern, value, re.I)
    return m.group(1) if m and m.lastindex else "unknown"


def _validate_version(tech: str, version: str) -> tuple[str, str]:
    if version == "unknown":
        return "unknown", "버전을 확인할 수 없습니다"
    if tech in VULNERABLE_VERSIONS and version in VULNERABLE_VERSIONS[tech]:
        return "vulnerable", f"{tech} {version} — 알려진 취약 버전 (CVE 등록됨)"
    return "ok", f"{tech} {version} — 알려진 치명적 취약점 없음"


# ── 핑거프린팅 메인 함수 ─────────────────────────────────

def fingerprint(url: str) -> dict:
    result: dict = {
        "url": url,
        "webserver": None, "webserver_version": "unknown",
        "os": None,
        "language": None,  "language_version": "unknown",
        "framework": [],
        "security_headers": [], "missing_security": [],
        "validation": [],
        "raw_headers": {},
    }

    try:
        resp = requests.get(
            url, timeout=10, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (VulnScanner-Fingerprint/1.0)"},
        )
    except requests.exceptions.ConnectionError:
        result["error"] = "연결 실패"
        return result
    except requests.exceptions.Timeout:
        result["error"] = "요청 타임아웃"
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body    = resp.text.lower()
    result["raw_headers"] = dict(resp.headers)

    # 웹서버
    for tech, sig in SIGNATURES["webserver"].items():
        val = headers.get(sig["header"], "")
        if re.search(sig["pattern"], val, re.I):
            result["webserver"]         = tech
            result["webserver_version"] = _extract_version(val, sig["pattern"])
            break

    # OS
    for tech, sig in SIGNATURES["os"].items():
        val = headers.get(sig["header"], "")
        if re.search(sig["pattern"], val, re.I):
            result["os"] = tech
            break

    # 언어
    for tech, sig in SIGNATURES["language"].items():
        val = headers.get(sig.get("header", ""), "")
        if re.search(sig["pattern"], val, re.I):
            result["language"]         = tech
            result["language_version"] = _extract_version(val, sig["pattern"])
            break

    # 프레임워크 / CMS
    for tech, sig in SIGNATURES["framework"].items():
        if "body" in sig:
            if re.search(sig["body"], body, re.I):
                result["framework"].append(tech)
        elif "header" in sig:
            val = headers.get(sig["header"], "")
            if re.search(sig["pattern"], val, re.I):
                result["framework"].append(tech)

    # 보안 헤더
    for name, key in SIGNATURES["security_headers"].items():
        if key in headers:
            result["security_headers"].append(name)
        else:
            result["missing_security"].append(name)

    # 버전 검증
    for tech, version in [
        (result["webserver"], result["webserver_version"]),
        (result["language"],  result["language_version"]),
    ]:
        if tech:
            status, message = _validate_version(tech, version)
            result["validation"].append({
                "tech": tech, "version": version,
                "status": status, "message": message,
            })

    return result


# ── 출력 ────────────────────────────────────────────────

_R = "\033[91m"; _G = "\033[92m"; _Y = "\033[93m"
_C = "\033[96m"; _W = "\033[97m"; _D = "\033[0m";  _B = "\033[1m"


def print_fingerprint(result: dict, label: str = "") -> None:
    print(f"\n{_B}{'='*55}{_D}")
    if label:
        print(f"{_B}  시나리오: {label}{_D}")
    print(f"{_B}  대상   : {result['url']}{_D}")
    print(f"{_B}{'='*55}{_D}")

    if result.get("error"):
        print(f"  {_R}[ERROR]{_D} {result['error']}")
        return

    ws  = result["webserver"] or "unknown"
    wv  = result["webserver_version"]
    os_ = result["os"] or "unknown"
    lg  = result["language"] or "unknown"
    lv  = result["language_version"]
    fw  = ", ".join(result["framework"]) if result["framework"] else "감지되지 않음"

    print(f"\n  {_C}[Web Server]{_D}  {ws} {wv}")
    print(f"  {_C}[OS]{_D}          {os_}")
    print(f"  {_C}[Language]{_D}    {lg} {lv}")
    print(f"  {_C}[Framework]{_D}   {fw}")

    print(f"\n  {_B}--- 버전 검증 ---{_D}")
    for v in result["validation"]:
        icon, color = {"ok": ("PASS", _G), "vulnerable": ("FAIL", _R)}.get(
            v["status"], ("WARN", _Y)
        )
        print(f"  {color}[{icon}]{_D} {v['message']}")

    print(f"\n  {_B}--- 보안 헤더 ---{_D}")
    for h in result["security_headers"]:
        print(f"  {_G}[존재]{_D} {h}")
    for h in result["missing_security"]:
        print(f"  {_R}[누락]{_D} {h}")
    print()
