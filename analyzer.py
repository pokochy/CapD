"""
core/analyzer.py — 주입 지점 분석기

두 가지 입력 소스를 모두 지원:
  1. parse_request(crawl_data: dict)  — raw dict 분석
  2. build_targets(pages: list[CrawledPage])  — CrawledPage 목록 분석

둘 다 동일한 List[ScanTarget]을 반환 → engine.py가 소비.
"""
from __future__ import annotations

import json
import logging
import urllib.parse as urlparse

from core.models import CrawledPage, ScanTarget

logger = logging.getLogger("Analyzer")

# 주입 가능한 input type 목록
_INJECTABLE_TYPES = {
    "text", "password", "email", "search", "url",
    "number", "tel", "hidden", "textarea",
}


class Analyzer:
    """크롤 데이터 → ScanTarget 변환기"""

    # ── 방식 1: raw dict ──────────────────────────────────────────

    def parse_request(self, crawl_data: dict) -> list[ScanTarget]:
        """
        크롤러 raw dict 하나를 받아 주입 가능한 ScanTarget 목록 반환.

        crawl_data 키:
          url     : 요청 URL (쿼리스트링 포함 가능)
          method  : HTTP 메서드 (기본 GET)
          headers : 헤더 dict
          body    : 요청 본문 (str 또는 dict)
        """
        targets: list[ScanTarget] = []

        url      = crawl_data.get("url", "")
        method   = crawl_data.get("method", "GET").upper()
        headers  = crawl_data.get("headers", {}) or {}
        raw_body = crawl_data.get("body", "")

        if not url:
            logger.warning("URL이 없는 crawl_data 무시됨")
            return targets

        # URL 쿼리 파라미터
        parsed_url = urlparse.urlparse(url)
        base_url   = url.split("?")[0]
        all_query  = {k: v[0] for k, v in urlparse.parse_qs(parsed_url.query).items()}

        for name in all_query:
            targets.append(ScanTarget(
                position = "query",
                url      = base_url,
                method   = method,
                param    = name,
                extra    = dict(all_query),
                found_on = url,
            ))

        # 요청 본문 (POST / PUT / PATCH)
        if method in ("POST", "PUT", "PATCH"):
            body_dict = self._parse_body(raw_body, headers, url)
            for name in body_dict:
                targets.append(ScanTarget(
                    position = "body",
                    url      = url,
                    method   = method,
                    param    = name,
                    extra    = dict(body_dict),
                    found_on = url,
                ))

        # 쿠키 / 헤더
        for h_name in headers:
            pos = "cookie" if h_name.lower() == "cookie" else "header"
            targets.append(ScanTarget(
                position = pos,
                url      = base_url,
                method   = method,
                param    = h_name,
                extra    = {},
                found_on = url,
            ))

        logger.debug("parse_request → ScanTarget %d개 (%s)", len(targets), url)
        return targets

    @staticmethod
    def _parse_body(raw_body, headers: dict, url: str) -> dict:
        """Content-Type에 따라 body를 dict로 변환."""
        if isinstance(raw_body, dict):
            return raw_body
        if not isinstance(raw_body, str) or not raw_body.strip():
            return {}

        content_type = next(
            (v.lower() for k, v in headers.items() if k.lower() == "content-type"),
            "",
        )

        if "application/json" in content_type:
            try:
                parsed = json.loads(raw_body)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                logger.warning("JSON 파싱 실패: %s", url)
                return {}

        if "application/x-www-form-urlencoded" in content_type:
            return {k: v[0] for k, v in urlparse.parse_qs(raw_body).items()}

        return {}

    # ── 방식 2: CrawledPage 목록 ─────────────────────────────────

    def build_targets(self, pages: list[CrawledPage]) -> list[ScanTarget]:
        """
        WebCrawler가 반환한 CrawledPage 목록을 ScanTarget 목록으로 변환.
        중복 (url + method + param)은 자동 제거.
        """
        targets : list[ScanTarget] = []
        seen    : set[str]         = set()

        for page in pages:
            # URL 쿼리 파라미터
            if page.query_params:
                base_url = page.url.split("?")[0]
                all_qp   = dict(page.query_params)
                for param_name in page.query_params:
                    key = f"query|GET|{base_url}|{param_name}"
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(ScanTarget(
                        position = "query",
                        url      = base_url,
                        method   = "GET",
                        param    = param_name,
                        extra    = dict(all_qp),
                        found_on = page.url,
                    ))

            # 폼 필드
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
                        position = "form_field",
                        url      = form.action,
                        method   = form.method,
                        param    = fld.name,
                        extra    = dict(base_data),
                        found_on = form.found_on,
                    ))

        url_p  = sum(1 for t in targets if t.position == "query")
        form_p = sum(1 for t in targets if t.position == "form_field")
        logger.info(
            "build_targets → ScanTarget %d개 (query: %d, form_field: %d)",
            len(targets), url_p, form_p,
        )
        return targets
