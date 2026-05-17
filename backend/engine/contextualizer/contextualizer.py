"""
engine/contextualizer/contextualizer.py
────────────────────────────────────────
1단계 (신규): 지능형 페이로드 생성기 (Contextualizer)

Crawler가 수집한 input_points와 Fingerprinter의 profile을 분석하여
각 파라미터·주입 위치에 가장 적합한 페이로드 서브셋을 골라
"강화된 input_points"를 Auditor에 전달한다.

핵심 기능
─────────
1. 파라미터 타입 추론
   - 이름 패턴(id, page, query...) + 기존 값 형태로 숫자·문자열·JSON을 구분

2. 콘텐츠 타입 감지
   - 크롤 응답 헤더의 Content-Type 으로 HTML·JSON·GraphQL endpoint를 식별

3. 기술 스택 기반 필터링
   - Fingerprinter가 탐지한 프레임워크 정보로 관련성 낮은 payload_group 제거
   - 예) Django 감지 → Jinja2 그룹 우선, Spring 감지 → spring_el 우선

4. WAF 존재 시 페이로드 수 축소
   - WAF가 감지되면 각 파라미터당 최대 페이로드 수를 절반으로 줄여
     탐지 확률을 낮추고 Mutator에서 우회 변종을 생성하도록 위임

반환
────
input_points 와 동일한 구조이되, 각 포인트에 다음 필드가 추가됨:
  - "content_type"   : "html" | "json" | "graphql" | "unknown"
  - "param_hints"    : {param_name: {"type": "numeric"|"string"|"json", "priority_groups": [str]}}
  - "waf_detected"   : bool
  - "max_payloads"   : int   (파라미터당 최대 페이로드 수)
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse, parse_qs

from utils.logger import get_logger

logger = get_logger("contextualizer")

# ── 파라미터 이름 → 타입 힌트 매핑 ────────────────────────────────────────────
_NUMERIC_PARAM_PATTERNS = re.compile(
    r"^(id|idx|num|page|p|offset|limit|count|seq|order|sort|"
    r"year|month|day|size|amount|qty|quantity|price|age)$",
    re.IGNORECASE,
)
_STRING_PARAM_PATTERNS = re.compile(
    r"^(q|query|search|keyword|s|name|title|text|message|"
    r"comment|content|desc|description|subject|body|input)$",
    re.IGNORECASE,
)
_JSON_PARAM_PATTERNS = re.compile(
    r"^(data|json|payload|body|params|filter|where|args)$",
    re.IGNORECASE,
)

# ── 기술 스택 → 우선 payload_group 매핑 ────────────────────────────────────────
_TECH_TO_PRIORITY_GROUPS: dict[str, list[str]] = {
    "django":     ["jinja2_twig"],
    "flask":      ["jinja2_twig"],
    "spring":     ["spring_el", "freemarker_thymeleaf"],
    "rails":      ["ruby_erb"],
    "express":    ["ejs_node"],
    "laravel":    ["jinja2_twig"],           # Blade는 Twig 문법 유사
    "wordpress":  ["reflected_basic"],
    "iis":        ["mssql_error", "reflected_basic"],
    "apache":     ["error_based", "reflected_basic"],
    "nginx":      [],                        # 특정 우선순위 없음
}

# WAF 존재 시 파라미터당 최대 페이로드 수
_WAF_MAX_PAYLOADS = int(os.getenv("WAF_MAX_PAYLOADS", "5"))
_NORMAL_MAX_PAYLOADS = int(os.getenv("NORMAL_MAX_PAYLOADS", "30"))


class Contextualizer:
    """
    Crawler 결과를 분석해 각 공격 포인트에 최적화된 컨텍스트를 부여한다.
    """

    def run(
        self,
        input_points: list[dict],
        profile: dict,
        response_meta: list[dict] | None = None,
    ) -> list[dict]:
        """
        파라미터:
          input_points  : Crawler.run() 반환값
          profile       : Fingerprinter.run() 반환값
          response_meta : [{url, content_type, status}] 크롤 응답 메타 (선택)

        반환:
          input_points 에 컨텍스트 필드가 추가된 새 리스트
        """
        waf_detected: bool = profile.get("waf_detected", False)
        technologies: list[str] = [t.lower() for t in profile.get("technologies", [])]
        max_payloads = _WAF_MAX_PAYLOADS if waf_detected else _NORMAL_MAX_PAYLOADS

        # response_meta를 URL → content_type 딕셔너리로 변환
        ct_map: dict[str, str] = {}
        for meta in (response_meta or []):
            ct_map[meta["url"]] = self._parse_content_type(meta.get("content_type", ""))

        enriched: list[dict] = []
        for point in input_points:
            base_url = self._strip_query(point["url"])
            content_type = ct_map.get(base_url, ct_map.get(point["url"], "html"))

            # GraphQL endpoint 패턴 감지
            if self._is_graphql(point["url"], content_type):
                content_type = "graphql"

            param_hints = {
                param: self._analyze_param(param, point, technologies)
                for param in point.get("params", [])
            }

            enriched.append({
                **point,
                "content_type": content_type,
                "param_hints": param_hints,
                "waf_detected": waf_detected,
                "max_payloads": max_payloads,
            })

            logger.debug(
                f"[Contextualizer] {point['url']} "
                f"ct={content_type} params={list(param_hints.keys())} "
                f"waf={waf_detected} max_payloads={max_payloads}"
            )

        logger.info(
            f"[Contextualizer] Enriched {len(enriched)} points | "
            f"waf={waf_detected} | tech={technologies}"
        )
        return enriched

    # ── 내부 헬퍼 ─────────────────────────────────────────────────────────────

    def _analyze_param(
        self,
        param: str,
        point: dict,
        technologies: list[str],
    ) -> dict:
        """파라미터 이름·기존 값으로 타입을 추론하고 우선 payload_group을 결정."""
        existing_value = point.get("param_values", {}).get(param, "")
        param_type = self._infer_type(param, existing_value)
        priority_groups = self._priority_groups(param_type, technologies)

        return {
            "type": param_type,
            "priority_groups": priority_groups,
        }

    def _infer_type(self, param: str, value: str) -> str:
        """파라미터 이름과 기존 값으로 타입 추론."""
        # 값 기반 우선 판단
        if value:
            if value.lstrip("-").isdigit():
                return "numeric"
            try:
                import json
                json.loads(value)
                return "json"
            except (ValueError, TypeError):
                pass

        # 이름 패턴 기반 판단
        if _NUMERIC_PARAM_PATTERNS.match(param):
            return "numeric"
        if _JSON_PARAM_PATTERNS.match(param):
            return "json"
        if _STRING_PARAM_PATTERNS.match(param):
            return "string"

        return "string"  # 기본값

    def _priority_groups(self, param_type: str, technologies: list[str]) -> list[str]:
        """
        파라미터 타입 + 기술 스택으로 우선 payload_group 목록을 결정.
        반환된 그룹이 Auditor에서 먼저 시도된다.
        """
        groups: list[str] = []

        # 기술 스택 기반 우선 그룹
        for tech in technologies:
            groups.extend(_TECH_TO_PRIORITY_GROUPS.get(tech, []))

        # 파라미터 타입 기반 추가 그룹
        if param_type == "numeric":
            # 숫자형 파라미터: SQLi가 가장 유효
            groups = ["error_based", "boolean_based", "time_based", "union_based"] + groups
        elif param_type == "json":
            # JSON 파라미터: JSON 인젝션 우선
            groups = ["json_injection"] + groups
        elif param_type == "string":
            # 문자열: SSTI + XSS 우선
            if not groups:
                groups = ["jinja2_twig", "reflected_basic", "error_based"]

        # 중복 제거 (순서 유지)
        seen: set[str] = set()
        deduped: list[str] = []
        for g in groups:
            if g not in seen:
                seen.add(g)
                deduped.append(g)
        return deduped

    @staticmethod
    def _parse_content_type(raw: str) -> str:
        raw = raw.lower()
        if "application/json" in raw or "text/json" in raw:
            return "json"
        if "graphql" in raw:
            return "graphql"
        if "text/html" in raw or "application/xhtml" in raw:
            return "html"
        return "unknown"

    @staticmethod
    def _is_graphql(url: str, content_type: str) -> bool:
        path = urlparse(url).path.lower()
        return (
            "graphql" in path
            or "/gql" in path
            or content_type == "graphql"
        )

    @staticmethod
    def _strip_query(url: str) -> str:
        p = urlparse(url)
        return p._replace(query="", fragment="").geturl()
