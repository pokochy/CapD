"""
main.py — 통합 웹 취약점 스캐너 v2.0 진입점

사용법:
    pip install aiohttp beautifulsoup4 requests pyyaml
    python main.py
"""
from __future__ import annotations

import logging
import os
import sys

from pipeline import VulnScanPipeline, _create_default_templates

BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                    통합 웹 취약점 스캐너  v2.0                     ║
║          Fingerprint → Crawl → Analyze → Scan → Report           ║
╚══════════════════════════════════════════════════════════════════╝
"""

DEFAULT_TARGET = "http://testphp.vulnweb.com"


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)-20s] %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> None:
    print(BANNER)

    # ── 설정 입력 ────────────────────────────────────────
    target = input(f"  스캔 URL [{DEFAULT_TARGET}]: ").strip()
    if not target:
        target = DEFAULT_TARGET
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    depth_in = input("  크롤링 깊이 (기본 2): ").strip()
    depth    = int(depth_in) if depth_in.isdigit() else 2

    pages_in = input("  최대 페이지 수 (기본 30): ").strip()
    max_pg   = int(pages_in) if pages_in.isdigit() else 30

    verbose  = input("  상세 로그 출력? (y/N): ").strip().lower() == "y"
    _setup_logging(verbose)

    # ── 기본 템플릿 준비 ─────────────────────────────────
    _create_default_templates("templates")

    # ── 파이프라인 실행 ──────────────────────────────────
    pipeline = VulnScanPipeline(
        target_url=target,
        template_dir="templates",
        max_depth=depth,
        max_pages=max_pg,
        crawl_concurrency=3,
        scan_workers=5,
        request_delay=0.3,
        output_json="scan_report.json",
    )

    try:
        findings = pipeline.run()
        sys.exit(0 if not findings else 1)   # 취약점 발견 시 exit code 1
    except KeyboardInterrupt:
        print("\n\n  [!] 사용자 중단")
        sys.exit(2)


if __name__ == "__main__":
    main()
