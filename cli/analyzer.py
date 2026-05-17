"""
analyzer.py — 주입 지점 분석기 (통합)

두 가지 입력 소스를 모두 지원:
  1. parse_request(crawl_data: dict)
       기존 방식 — 수동 작성하거나 외부 크롤러가 전달하는 raw dict 분석
       (query / body / cookie / header 포지션 추출)

  2. build_targets(pages: list[CrawledPage])
       신규 방식 — WebCrawler 가 반환한 CrawledPage 목록 분석
       (url_param / form_field 포지션 추출)

둘 다 동일한 ScanTarget 리스트를 반환한다.
"""
from __future__ import annotations

import logging
import urllib.parse as urlparse

from models import CrawledPage, ScanTarget

logger = logging.getLogger("Analyzer")

# form_field 에서 주입 가능한 input type 목록
_INJECTABLE_TYPES = {
    "text", "password", "email", "search", "url",
    "number", "tel", "hidden", "textarea",
}


class Analyzer:
    """크롤 데이터 → ScanTarget 변환기"""

    # ── 방식 1: raw dict (기존 analyzer.py) ────────────

    def parse_request(self, crawl_data: dict) -> list[ScanTarget]:
        """
        크롤러 raw dict 하나를 받아 주입 가능한 ScanTarget 목록을 반환.

        crawl_data 예시:
        {
            'url': 'http://example.com/page?id=1',
            'method': 'POST',
            'headers': {'Cookie': 'session=abc', 'Referer': '...'},
            'body': {'username': 'test', 'password': 'test'}
        }
        """
        targets: list[ScanTarget] = []
        url     = crawl_data["url"]
        method  = crawl_data["method"].upper()
        headers = crawl_data.get("headers", {})

        # 1. Query (URL 파라미터)
        parsed = urlparse.urlparse(url)
        query_params = urlparse.parse_qs(parsed.query)
        base_url = url.split("?")[0]
        all_query = {k: v[0] for k, v in query_params.items()}

        for name in query_params:
            targets.append(ScanTarget(
                position="query",
                url=base_url,
                method="GET",
                name=name,
                base_data=dict(all_query),
                found_on=url,
            ))

        # 2. Body (POST 폼 데이터)
        if method == "POST" and isinstance(crawl_data.get("body"), dict):
            body = crawl_data["body"]
            for name in body:
                targets.append(ScanTarget(
                    position="body",
                    url=url,
                    method="POST",
                    name=name,
                    base_data=dict(body),
                    found_on=url,
                ))

        # 3. Cookie / Header
        for h_name, h_value in headers.items():
            pos = "cookie" if h_name.lower() == "cookie" else "header"
            targets.append(ScanTarget(
                position=pos,
                url=base_url,
                method=method,
                name=h_name,
                base_data={},
                found_on=url,
            ))

        logger.debug("parse_request → ScanTarget %d개 (%s)", len(targets), url)
        return targets

    # ── 방식 2: CrawledPage 목록 (신규 ScanTargetBuilder) ─

    def build_targets(self, pages: list[CrawledPage]) -> list[ScanTarget]:
        """
        WebCrawler 가 반환한 CrawledPage 목록을 ScanTarget 목록으로 변환.
        중복 (url + method + param) 은 자동 제거.
        """
        targets: list[ScanTarget] = []
        seen: set[str] = set()

        for page in pages:
            # ── URL 쿼리 파라미터 ──────────────────────
            if page.query_params:
                base_url = page.url.split("?")[0]
                all_qp   = dict(page.query_params)
                for param_name in page.query_params:
                    key = f"query|GET|{base_url}|{param_name}"
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(ScanTarget(
                        position="query",
                        url=base_url,
                        method="GET",
                        name=param_name,
                        base_data=dict(all_qp),
                        found_on=page.url,
                    ))

            # ── 폼 필드 ────────────────────────────────
            for form in page.forms:
                base_data = {
                    f.name: (f.options[0] if f.options else f.value)
                    for f in form.fields
                }
                for fld in form.fields:
                    if fld.field_type not in _INJECTABLE_TYPES:
                        continue
                    key = f"form_field|{form.method}|{form.action}|{fld.name}"
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(ScanTarget(
                        position="form_field",
                        url=form.action,
                        method=form.method,
                        name=fld.name,
                        base_data=dict(base_data),
                        found_on=form.found_on,
                    ))

        url_p  = sum(1 for t in targets if t.position == "query")
        form_p = sum(1 for t in targets if t.position == "form_field")
        logger.info(
            "build_targets → ScanTarget %d개 (query: %d, form_field: %d)",
            len(targets), url_p, form_p,
        )
        return targets
