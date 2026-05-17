"""
main.py — 통합 웹 취약점 스캐너 진입점

사용법:
  python main.py                   # FastAPI 서버 실행 (기본)
  python main.py --server          # FastAPI 서버 실행
  python main.py --cli             # 대화형 CLI 스캔
  python main.py --cli --url http://example.com --depth 2 --pages 30
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from dotenv import load_dotenv

load_dotenv()

BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                    통합 웹 취약점 스캐너  v2.0                     ║
║     Fingerprint → Crawl → Contextualize → Audit → Validate      ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ── CLI 모드 ──────────────────────────────────────────────────────────────────

async def _run_cli(target_url: str, max_depth: int, max_pages: int, verbose: bool) -> int:
    """
    6단계 파이프라인을 CLI 모드로 실행.
    반환값: 취약점 발견 시 1, 없으면 0 (exit code).
    """
    import logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)-20s] %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    from engine.profiler.fingerprint import Fingerprinter, print_fingerprint
    from engine.crawler.crawler import Crawler
    from engine.contextualizer.contextualizer import Contextualizer
    from engine.auditor.auditor import Auditor
    from engine.validator.validator import Validator
    from utils.reporter import generate_html, save_json, make_report_dir

    W = 68

    print(BANNER)
    print(f"  대상: {target_url}")
    print(f"  크롤 깊이: {max_depth}  최대 페이지: {max_pages}")
    print()

    # ── 1. Fingerprinting ─────────────────────────────────────────────────────
    print("─" * W)
    print("  [Phase 1] Fingerprinting — 기술 스택·WAF 탐지")
    print("─" * W)
    profiler = Fingerprinter()
    profile = await profiler.run(target_url)
    print_fingerprint(profile)

    # ── 2. Crawling ───────────────────────────────────────────────────────────
    print("─" * W)
    print("  [Phase 2] Crawling — 공격 표면 수집")
    print("─" * W)
    # SCAN_MAX_DEPTH·SCAN_CONCURRENCY 환경변수 임시 오버라이드
    os.environ["SCAN_MAX_DEPTH"] = str(max_depth)

    crawler = Crawler()
    result = await crawler.run(target_url)
    if isinstance(result, tuple):
        input_points, response_meta = result[0], result[1]
    else:
        input_points, response_meta = result, []

    pages_count = len(crawler.visited)
    print(f"\n  크롤링 완료: {pages_count}페이지, 입력 포인트 {len(input_points)}개")

    if not input_points:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target_url)
        if parsed.query:
            input_points.append({
                "url": target_url, "method": "GET",
                "position": "query",
                "params": list(parse_qs(parsed.query).keys()),
            })

    # ── 3. Contextualizing ────────────────────────────────────────────────────
    print("\n" + "─" * W)
    print("  [Phase 3] Contextualizing — 파라미터별 페이로드 최적화")
    print("─" * W)
    contextualizer = Contextualizer()
    enriched_points = contextualizer.run(
        input_points=input_points,
        profile=profile,
        response_meta=response_meta,
    )
    waf_cnt = sum(1 for p in enriched_points if p.get("waf_detected"))
    json_cnt = sum(1 for p in enriched_points if p.get("content_type") == "json")
    print(f"  포인트: {len(enriched_points)}개  (JSON:{json_cnt}  WAF감지:{waf_cnt})")

    # ── 4. Auditing ───────────────────────────────────────────────────────────
    print("\n" + "─" * W)
    print("  [Phase 4] Auditing — 페이로드 주입 스캔")
    print("─" * W)
    auditor = Auditor()
    raw_findings = await auditor.run(enriched_points)
    print(f"  원시 발견: {len(raw_findings)}건")

    # ── 5. Validation ─────────────────────────────────────────────────────────
    print("\n" + "─" * W)
    print("  [Phase 5] Validation — 오탐 제거")
    print("─" * W)
    validator = Validator()
    findings = await validator.run(raw_findings)
    print(f"  확정 취약점: {len(findings)}건")

    # ── 6. Report ─────────────────────────────────────────────────────────────
    print("\n" + "─" * W)
    print("  [Phase 6] Report — 보고서 생성")
    print("─" * W)
    report_dir = make_report_dir("reports")
    json_path  = os.path.join(report_dir, "scan_report.json")
    html_path  = os.path.join(report_dir, "scan_report.html")

    # finding dict 정규화 (API 모드와 동일한 키)
    finding_dicts = [
        {
            "vulnerability":  f.get("vuln_name", f.get("vulnerability", "Unknown")),
            "vuln_name":      f.get("vuln_name", ""),
            "severity":       f.get("severity", "info"),
            "matched_at":     f.get("matched_at", ""),
            "payload":        f.get("payload", ""),
            "payload_group":  f.get("payload_group"),
            "template_id":    f.get("template_id"),
            "evidence":       f.get("evidence"),
            "strategy":       f.get("strategy"),
        }
        for f in findings
    ]

    save_json(finding_dicts, profile, pages_count, target_url, json_path)
    generate_html(finding_dicts, profile, pages_count, target_url, html_path)

    # 콘솔 요약
    print()
    SEV_ICON = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]",
                "low": "[LOW]", "info": "[INFO]"}
    if finding_dicts:
        print(f"\n  {'─'*W}")
        print(f"  발견된 취약점 {len(finding_dicts)}건")
        print(f"  {'─'*W}")
        for i, f in enumerate(finding_dicts, 1):
            sev = f.get("severity", "info")
            print(f"  [{i:02d}] {SEV_ICON.get(sev, sev.upper())} {f.get('vulnerability', '')}")
            print(f"       URL    : {f.get('matched_at', '')}")
            print(f"       페이로드: {f.get('payload', '')}")
    else:
        print("\n  발견된 취약점이 없습니다.")

    print(f"\n  결과 폴더: {report_dir}")
    return 1 if finding_dicts else 0


def _cli_mode(args: argparse.Namespace) -> None:
    target = args.url
    if not target:
        print(BANNER)
        target = input("  스캔 URL [http://testphp.vulnweb.com]: ").strip()
        if not target:
            target = "http://testphp.vulnweb.com"
        depth_in = input("  크롤링 깊이 (기본 2): ").strip()
        args.depth = int(depth_in) if depth_in.isdigit() else 2
        pages_in = input("  최대 페이지 수 (기본 30): ").strip()
        args.pages = int(pages_in) if pages_in.isdigit() else 30
        args.verbose = input("  상세 로그? (y/N): ").strip().lower() == "y"

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    try:
        exit_code = asyncio.run(_run_cli(target, args.depth, args.pages, args.verbose))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n  [!] 사용자 중단")
        sys.exit(2)


# ── 서버 모드 ─────────────────────────────────────────────────────────────────

def _server_mode() -> None:
    import uvicorn
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from contextlib import asynccontextmanager

    from models.database import init_db
    from api.scan import router as scan_router
    from api.reports import router as reports_router
    from utils.logger import get_logger

    log = get_logger("main")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        log.info("Starting Vulnerability Scanner API...")
        await init_db()
        log.info("Database initialized (SQLite)")
        yield
        log.info("Shutting down...")

    app = FastAPI(
        title="Vulnerability Scanner API",
        description="SSTI, SQLi, XSS, Command Injection 등 웹 취약점 자동 스캔 API",
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    _origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(scan_router)
    app.include_router(reports_router)

    @app.get("/", tags=["health"])
    async def root():
        return {"status": "ok", "service": "vulnerability-scanner", "version": "2.0.0"}

    @app.get("/health", tags=["health"])
    async def health():
        return {"status": "healthy"}

    host  = os.getenv("APP_HOST", "0.0.0.0")
    port  = int(os.getenv("APP_PORT", "8000"))
    reload = os.getenv("APP_ENV", "development") == "development"
    level = os.getenv("LOG_LEVEL", "info").lower()

    print(BANNER)
    print(f"  서버 시작: http://{host}:{port}")
    print(f"  API 문서:  http://localhost:{port}/docs")
    print()

    uvicorn.run(app, host=host, port=port, reload=reload, log_level=level)


# ── 진입점 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="통합 웹 취약점 스캐너 v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python main.py                          # FastAPI 서버 실행
  python main.py --server                 # FastAPI 서버 실행
  python main.py --cli                    # 대화형 CLI 스캔
  python main.py --cli --url http://target.com
  python main.py --cli --url http://target.com --depth 3 --pages 50 --verbose
        """,
    )
    parser.add_argument("--server", action="store_true", help="FastAPI 서버 모드 실행")
    parser.add_argument("--cli",    action="store_true", help="대화형 CLI 스캔 모드")
    parser.add_argument("--url",    type=str, default="",  help="스캔 대상 URL (CLI 모드)")
    parser.add_argument("--depth",  type=int, default=2,   help="크롤링 깊이 (기본: 2)")
    parser.add_argument("--pages",  type=int, default=30,  help="최대 페이지 수 (기본: 30)")
    parser.add_argument("--verbose",action="store_true",   help="상세 로그 출력")

    args = parser.parse_args()

    if args.cli:
        _cli_mode(args)
    else:
        # --server 명시 또는 인수 없을 때 서버 모드
        _server_mode()


if __name__ == "__main__":
    main()
