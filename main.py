"""
main.py — 웹 취약점 스캐너 CLI 진입점

사용 예시:
  python main.py --url https://example.com/search?q=test --templates templates/xss
  python main.py --url https://example.com/login --template templates/sqli/sql_injection_base.yaml --method POST --body "username=admin&password=test"
  python main.py --url https://example.com --templates templates/ --output-json results.json
"""
from __future__ import annotations

import argparse
import logging
import sys
import urllib.parse as urlparse
from pathlib import Path

from core.analyzer        import Analyzer
from core.engine          import ScanEngine
from core.logger          import setup_logging
from core.models          import CrawledPage, FormDef, FieldDef
from core.reporter        import print_summary, save_json, save_text
from core.template_loader import load_templates
from core.validator       import validate_url, validate_rate_limit, validate_timeout, ValidationError

logger = logging.getLogger("Main")


# ──────────────────────────────────────────────
# CLI 인수 정의
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "main.py",
        description = "템플릿 기반 웹 취약점 스캐너",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
예시:
  # URL 쿼리 파라미터 스캔
  python main.py --url "https://example.com/search?q=test" --templates templates/xss

  # POST 요청 스캔
  python main.py --url "https://example.com/login" \\
    --method POST --body "username=admin&password=test" \\
    --templates templates/sqli

  # 단일 템플릿 파일 지정
  python main.py --url "https://example.com/?id=1" \\
    --template templates/sqli/sql_injection_base.yaml

  # JSON 결과 저장
  python main.py --url "https://example.com/?id=1" \\
    --templates templates/ --output-json logs/result.json

  # 템플릿 목록 확인
  python main.py --list-templates
        """,
    )

    # 대상
    target = p.add_argument_group("대상 설정")
    target.add_argument("--url",    metavar="URL",    help="스캔 대상 URL")
    target.add_argument("--method", metavar="METHOD", default="GET",
                        choices=["GET", "POST", "PUT", "PATCH"],
                        help="HTTP 메서드 (기본: GET)")
    target.add_argument("--body",   metavar="BODY",   default="",
                        help="요청 본문 (POST 등에서 사용. form-encoded 또는 JSON 문자열)")
    target.add_argument("--header", metavar="KEY:VAL", action="append", default=[],
                        dest="headers", help="추가 헤더 (여러 번 지정 가능)")
    target.add_argument("--cookie", metavar="KEY=VAL", action="append", default=[],
                        dest="cookies", help="쿠키 (여러 번 지정 가능)")

    # 템플릿
    tmpl = p.add_argument_group("템플릿 설정")
    tmpl_group = tmpl.add_mutually_exclusive_group()
    tmpl_group.add_argument("--template",  metavar="FILE",
                            help="단일 템플릿 YAML 파일 경로")
    tmpl_group.add_argument("--templates", metavar="DIR",
                            help="템플릿 디렉터리 경로 (하위 전체 로드)")
    tmpl.add_argument("--category", metavar="CAT", action="append", default=[],
                      dest="categories",
                      help="로드할 카테고리 (--templates 사용 시). 예: --category xss --category sqli")
    tmpl.add_argument("--list-templates", action="store_true",
                      help="사용 가능한 템플릿 목록 출력 후 종료")

    # 요청 설정
    req = p.add_argument_group("요청 설정")
    req.add_argument("--timeout",  type=float, default=10.0,
                     metavar="SEC", help="HTTP 타임아웃 (초, 기본: 10)")
    req.add_argument("--rate",     type=float, default=5.0,
                     metavar="RPS", help="초당 요청 수 제한 (기본: 5.0)")
    req.add_argument("--concurrency", type=int, default=10,
                     metavar="N", help="최대 동시 요청 수 (기본: 10)")
    req.add_argument("--stop-on-hit", action="store_true",
                     help="취약점 발견 시 해당 타겟 나머지 페이로드 건너뜀")

    # 출력
    out = p.add_argument_group("출력 설정")
    out.add_argument("--output-json", metavar="FILE",
                     help="JSON 결과 저장 경로 (예: logs/result.json)")
    out.add_argument("--output-txt",  metavar="FILE",
                     help="텍스트 결과 저장 경로 (예: logs/result.txt)")
    out.add_argument("--log-file",    metavar="FILE",
                     help="로그 파일 저장 경로")
    out.add_argument("--log-level",   default="INFO",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                     help="로그 레벨 (기본: INFO)")
    out.add_argument("--quiet",       action="store_true",
                     help="콘솔 출력 최소화 (취약점 발견만 표시)")

    return p


# ──────────────────────────────────────────────
# 인수 파싱 도우미
# ──────────────────────────────────────────────

def _parse_headers(raw_list: list[str]) -> dict[str, str]:
    """'Key:Value' 형식 목록 → dict 변환."""
    result = {}
    for item in raw_list:
        if ":" not in item:
            logger.warning("잘못된 헤더 형식 (무시): %r  (올바른 형식: Key:Value)", item)
            continue
        k, _, v = item.partition(":")
        result[k.strip()] = v.strip()
    return result


def _parse_cookies(raw_list: list[str]) -> dict[str, str]:
    """'key=value' 형식 목록 → dict 변환."""
    result = {}
    for item in raw_list:
        if "=" not in item:
            logger.warning("잘못된 쿠키 형식 (무시): %r  (올바른 형식: key=value)", item)
            continue
        k, _, v = item.partition("=")
        result[k.strip()] = v.strip()
    return result


# ──────────────────────────────────────────────
# 메인 로직
# ──────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # 로깅 초기화
    setup_logging(
        level    = args.log_level,
        log_file = args.log_file,
        quiet    = args.quiet,
    )

    # ── 템플릿 목록 출력 모드 ─────────────────────
    if args.list_templates:
        root = args.templates or "templates"
        try:
            tmpls = load_templates(root, args.categories or None)
        except FileNotFoundError as exc:
            print(f"오류: {exc}", file=sys.stderr)
            return 1

        print(f"\n사용 가능한 템플릿 ({root}):\n")
        for t in tmpls:
            print(
                f"  [{t.severity.upper():8}] {t.id:35} "
                f"| {t.category:10} | {t.name}"
            )
        print(f"\n총 {len(tmpls)}개\n")
        return 0

    # ── 대상 URL 필수 확인 ────────────────────────
    if not args.url:
        parser.error("--url 또는 --list-templates 중 하나를 지정해야 합니다.")

    # ── 입력 검증 ─────────────────────────────────
    try:
        url = validate_url(args.url)
    except ValidationError as exc:
        logger.error("URL 검증 실패: %s", exc)
        return 1

    try:
        timeout = validate_timeout(args.timeout)
        rate    = validate_rate_limit(args.rate)
    except ValidationError as exc:
        logger.error("설정 검증 실패: %s", exc)
        return 1

    # ── 템플릿 경로 결정 ──────────────────────────
    template_file = args.template
    templates_dir = args.templates

    if not template_file and not templates_dir:
        # 기본값: ./templates 디렉터리
        templates_dir = "templates"
        if not Path(templates_dir).exists():
            logger.error(
                "--template 또는 --templates 를 지정하거나 "
                "'templates/' 디렉터리를 생성하세요."
            )
            return 1

    # ── 헤더 / 쿠키 파싱 ─────────────────────────
    extra_headers = _parse_headers(args.headers)
    extra_cookies = _parse_cookies(args.cookies)

    # 쿠키를 Cookie 헤더로 통합
    if extra_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in extra_cookies.items())
        existing   = extra_headers.get("Cookie", "")
        extra_headers["Cookie"] = f"{existing}; {cookie_str}".lstrip("; ")

    # ── crawl_data 구성 ───────────────────────────
    crawl_data = {
        "url":     url,
        "method":  args.method,
        "headers": extra_headers,
        "body":    args.body,
    }

    # ── ScanTarget 생성 ───────────────────────────
    analyzer = Analyzer()
    targets  = analyzer.parse_request(crawl_data)

    if not targets:
        logger.warning(
            "주입 가능한 파라미터가 없습니다. "
            "URL에 쿼리스트링이나 POST body를 포함하세요."
        )
        return 0

    logger.info("추출된 ScanTarget: %d개", len(targets))

    # ── 엔진 초기화 ───────────────────────────────
    categories = args.categories or None

    if template_file:
        # 단일 파일 → 임시 디렉터리에 심어서 로드
        tmpl_path = Path(template_file)
        if not tmpl_path.exists():
            logger.error("템플릿 파일을 찾을 수 없습니다: %s", tmpl_path)
            return 1
        # 부모 디렉터리를 루트로, 파일명 기준 카테고리는 stem
        engine = ScanEngine(
            templates_root   = str(tmpl_path.parent.parent),
            categories       = [tmpl_path.parent.name],
            template_ids     = [tmpl_path.stem.split(".")[0]],
            request_timeout  = timeout,
            max_concurrency  = args.concurrency,
            requests_per_sec = rate,
        )
        # 로드 실패 시 단일 파일 직접 파싱으로 대체
        if not engine.templates:
            from core.template_loader import _parse_template
            try:
                cat  = tmpl_path.parent.name
                tmpl = _parse_template(tmpl_path, cat)
                engine.templates = [tmpl]
                logger.info("단일 템플릿 직접 로드: %s", tmpl.id)
            except Exception as exc:
                logger.error("템플릿 파싱 실패: %s", exc)
                return 1
    else:
        try:
            engine = ScanEngine(
                templates_root   = templates_dir,
                categories       = categories,
                request_timeout  = timeout,
                max_concurrency  = args.concurrency,
                requests_per_sec = rate,
            )
        except FileNotFoundError as exc:
            logger.error("%s", exc)
            return 1

    if not engine.templates:
        logger.error("로드된 템플릿이 없습니다.")
        return 1

    logger.info(
        "스캔 시작 — 대상: %s | 템플릿: %d개 | 타임아웃: %ss | RPS: %s",
        url, len(engine.templates), timeout, rate,
    )

    # ── 스캔 실행 ─────────────────────────────────
    results = engine.run(targets, stop_on_first_hit=args.stop_on_hit)

    # ── 결과 출력 ─────────────────────────────────
    if not args.quiet:
        print_summary(results)

    if args.output_json:
        save_json(results, args.output_json)
    if args.output_txt:
        save_text(results, args.output_txt)

    # 취약점이 발견되면 종료 코드 2 반환 (CI/CD 파이프라인용)
    vulns = [r for r in results if r.matched]
    return 2 if vulns else 0


if __name__ == "__main__":
    sys.exit(main())
