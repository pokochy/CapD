"""
tests/test_runner.py
─────────────────────
프론트엔드 없이 백엔드 단독 동작을 검증하는 CLI 테스트 러너.

사용법:
  python tests/test_runner.py --url https://example.com
  python tests/test_runner.py --url https://example.com --templates ssti-basic xss-basic
  python tests/test_runner.py --demo   # 실제 HTTP 요청 없이 엔진 로직만 확인
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import os

# 프로젝트 루트를 sys.path에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from engine.templates.loader import template_loader
from utils.logger import get_logger

logger = get_logger("test_runner")

# ── ANSI 색상 ────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEV_COLOR = {
    "critical": RED,
    "high":     "\033[35m",
    "medium":   YELLOW,
    "low":      GREEN,
    "info":     CYAN,
}


def print_banner():
    print(f"""{BOLD}{CYAN}
╔══════════════════════════════════════════════╗
║       Vulnerability Scanner — Test CLI       ║
║         Backend Standalone Verifier          ║
╚══════════════════════════════════════════════╝{RESET}
""")


def test_template_loading():
    """템플릿 로딩 및 파싱 검증."""
    print(f"\n{BOLD}[1/4] Template Loading Test{RESET}")
    templates = template_loader.load_all()
    assert templates, "No templates loaded!"

    for t in templates:
        payloads = template_loader.get_all_payloads(t)
        matchers = template_loader.compile_matchers(t)
        print(f"  {GREEN}✓{RESET} [{t['id']}] "
              f"{len(payloads)} payloads, {len(matchers)} matchers — "
              f"severity: {SEV_COLOR.get(t['info']['severity'], '')}{t['info']['severity']}{RESET}")

    print(f"  → Loaded {len(templates)} templates successfully\n")
    return templates


def test_matcher_logic():
    """Matcher 정규식 로직 검증 (HTTP 요청 없음)."""
    print(f"{BOLD}[2/4] Matcher Logic Test{RESET}")

    cases = [
        ("ssti-basic", "The result is 49 here",        True,  "arithmetic_result_49"),
        ("ssti-basic", "The result is 149 here",       False, "arithmetic_result_49"),  # 숫자에 붙음
        ("ssti-basic", "value=7777777 computed",       True,  "string_multiplication_result"),
        ("xss-basic",  "<script>alert(1)</script>",    True,  "script_tag_reflected"),
        ("xss-basic",  "safe output here",             False, "script_tag_reflected"),
        ("sqli-basic", "You have an error in your SQL syntax", True, "mysql_error"),
    ]

    passed = 0
    for tmpl_id, body, expected, matcher_name in cases:
        tmpl = template_loader.load_by_id(tmpl_id)
        if not tmpl:
            print(f"  {YELLOW}?{RESET} Template not found: {tmpl_id}")
            continue
        matchers = template_loader.compile_matchers(tmpl)

        # 특정 matcher만 테스트
        target = next((m for m in matchers if m["name"] == matcher_name), None)
        if not target:
            print(f"  {YELLOW}?{RESET} Matcher not found: {matcher_name}")
            continue

        result = any(p.search(body) for p in target["patterns"])
        ok = result == expected
        status = f"{GREEN}✓ PASS{RESET}" if ok else f"{RED}✗ FAIL{RESET}"
        print(f"  {status} [{tmpl_id}:{matcher_name}] body={body[:40]!r} → expected={expected}, got={result}")
        if ok:
            passed += 1

    print(f"  → {passed}/{len(cases)} matcher tests passed\n")


def test_payload_groups():
    """payload_groups 구조 및 평탄화 확인."""
    print(f"{BOLD}[3/4] Payload Groups Test{RESET}")
    templates = template_loader.load_all()
    for t in templates:
        groups = t.get("payload_groups", [])
        all_payloads = template_loader.get_all_payloads(t)
        print(f"  {CYAN}▸{RESET} [{t['id']}]")
        for g in groups:
            print(f"      group={g['group']!r:30s} engine={g['engine']!r}")
        print(f"      total flattened payloads: {len(all_payloads)}")
    print()


async def test_live_scan(url: str, template_ids: list[str] | None = None):
    """실제 URL에 대한 풀 파이프라인 실행 테스트."""
    print(f"{BOLD}[4/4] Live Scan Test{RESET}")
    print(f"  Target : {CYAN}{url}{RESET}")
    print(f"  Templates: {template_ids or 'all'}\n")

    from engine.profiler.fingerprint import Fingerprinter
    from engine.crawler.crawler import Crawler
    from engine.auditor.auditor import Auditor
    from engine.validator.validator import Validator

    # Profiler
    print(f"  {YELLOW}▶ Profiling...{RESET}")
    profiler = Fingerprinter()
    profile = await profiler.run(url)
    print(f"    Server     : {profile.get('server', 'unknown')}")
    print(f"    Technologies: {profile.get('technologies', [])}")
    print(f"    WAF        : {profile.get('waf') or 'None detected'}")
    print(f"    Response   : {profile.get('status_code')} ({profile.get('response_time_ms')}ms)")

    # Crawler
    print(f"\n  {YELLOW}▶ Crawling...{RESET}")
    crawler = Crawler()
    input_points = await crawler.run(url)
    print(f"    Pages visited   : {len(crawler.visited)}")
    print(f"    Input points    : {len(input_points)}")
    for pt in input_points[:5]:
        print(f"      → [{pt['method']}] {pt['url']} params={pt['params']}")
    if len(input_points) > 5:
        print(f"      ... and {len(input_points)-5} more")

    if not input_points:
        print(f"  {YELLOW}  No input points found. Skipping audit.{RESET}")
        return

    # Auditor
    print(f"\n  {YELLOW}▶ Auditing...{RESET}")
    auditor = Auditor()
    raw_findings = await auditor.run(input_points, template_ids)
    print(f"    Raw findings: {len(raw_findings)}")

    # Validator
    print(f"\n  {YELLOW}▶ Validating...{RESET}")
    validator = Validator()
    findings = await validator.run(raw_findings)
    print(f"    Confirmed findings: {len(findings)}")

    # 결과 출력
    if findings:
        print(f"\n  {BOLD}{RED}⚠ VULNERABILITIES FOUND:{RESET}")
        for i, f in enumerate(findings, 1):
            sev_c = SEV_COLOR.get(f["severity"], "")
            print(f"\n  [{i}] {sev_c}{f['severity'].upper()}{RESET} — {f['vuln_name']}")
            print(f"       Template  : {f['template_id']}")
            print(f"       URL       : {f['matched_at']}")
            print(f"       Payload   : {f['payload']!r}")
            print(f"       Group     : {f.get('payload_group')}")
            print(f"       Matcher   : {f.get('matcher_name')}")
            if f.get("evidence"):
                print(f"       Evidence  : {f['evidence'][:100]}...")
    else:
        print(f"\n  {GREEN}✓ No vulnerabilities confirmed.{RESET}")

    # JSON 저장
    output_path = f"scan_result_{url.split('//')[-1].split('/')[0]}.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump({"target": url, "findings": findings, "profile": profile}, fh, indent=2, default=str)
    print(f"\n  {GREEN}✓ Results saved: {output_path}{RESET}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Vulnerability Scanner — Backend Test CLI")
    parser.add_argument("--url",       help="Target URL to scan", default=None)
    parser.add_argument("--templates", nargs="*", help="Template IDs to use (default: all)")
    parser.add_argument("--demo",      action="store_true", help="Run offline demo tests only (no HTTP)")
    args = parser.parse_args()

    # 오프라인 테스트
    test_template_loading()
    test_matcher_logic()
    test_payload_groups()

    # 라이브 스캔
    if args.demo:
        print(f"{GREEN}✓ Demo mode complete (no HTTP requests made){RESET}\n")
        return

    if not args.url:
        print(f"{YELLOW}Tip: Pass --url https://target.com to run a live scan{RESET}")
        print(f"{YELLOW}     Pass --demo to run offline tests only{RESET}\n")
        return

    asyncio.run(test_live_scan(args.url, args.templates))


if __name__ == "__main__":
    main()
