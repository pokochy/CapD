"""
engine/auditor/auditor.py
──────────────────────────
3·4단계: 입력 포인트에 페이로드를 주입하고 응답을 분석.
[업그레이드 v2]

변경 내역
──────────
1. Contextualizer 연동
   - 각 포인트의 content_type·param_hints·priority_groups를 참조
   - priority_groups에 속한 payload_group을 먼저 시도하여 효율 향상

2. JSON·GraphQL 주입 분기
   - content_type == "json"     → post_json() 으로 JSON 바디 주입
   - content_type == "graphql"  → post_graphql() 로 variables 주입
   - 기존 HTML form/query 경로는 그대로 유지

3. Mutator 연동
   - 각 페이로드를 Mutator.mutate_all()로 변종 생성 후 순차 시도
   - WAF 탐지 시 더 많은 변종 자동 생성
   - finding에 "strategy" 필드 추가 (어떤 mutation이 성공했는지 기록)

4. max_payloads 준수
   - Contextualizer가 설정한 파라미터당 최대 페이로드 수 초과 시 중단

5. GraphQL 전용 쿼리 템플릿
   - 기본 search/input/filter 변수명으로 introspection 쿼리도 시도
"""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from engine.templates.loader import template_loader
from engine.mutator.mutator import Mutator
from utils.http_client import HttpClient
from utils.logger import get_logger

logger = get_logger("auditor")
_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "5"))

# GraphQL: 페이로드를 주입할 기본 쿼리 템플릿 (변수명 → 쿼리 매핑)
_GQL_QUERY_TEMPLATES: dict[str, str] = {
    "q":      "query Search($q: String) { search(query: $q) { id } }",
    "query":  "query Search($query: String) { search(query: $query) { id } }",
    "input":  "query Q($input: String) { field(input: $input) { id } }",
    "filter": "query Q($filter: String) { items(filter: $filter) { id } }",
    "id":     "query Q($id: ID) { node(id: $id) { id } }",
    "_default": "query Q($value: String) { search(input: $value) { id } }",
}


class Auditor:
    """
    각 입력 포인트에 대해 템플릿 페이로드를 주입하고
    matcher로 응답을 검사하여 취약점 후보를 반환.
    """

    def __init__(self) -> None:
        self._mutator = Mutator()

    async def run(
        self,
        input_points: list[dict],
        template_ids: list[str] | None = None,
    ) -> list[dict]:
        """
        파라미터:
          input_points : Contextualizer.run() 반환값
                         (content_type·param_hints·waf_detected·max_payloads 포함)
          template_ids : 지정 시 해당 템플릿만 사용, None이면 전체

        반환:
          [{
            template_id, vuln_name, severity, matched_at,
            payload, payload_group, matcher_name, evidence,
            strategy, content_type   ← [신규]
          }, ...]
        """
        templates = template_loader.load_all()
        if template_ids:
            templates = [t for t in templates if t.get("id") in template_ids]

        findings: list[dict] = []
        semaphore = asyncio.Semaphore(_CONCURRENCY)

        tasks = [
            self._audit_point(point, tmpl, semaphore)
            for point in input_points
            for tmpl in templates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        logger.info(f"[Auditor] Total findings: {len(findings)}")
        return findings

    # ── 포인트 × 템플릿 감사 ──────────────────────────────────────────────────

    async def _audit_point(
        self, point: dict, template: dict, semaphore: asyncio.Semaphore
    ) -> list[dict]:
        async with semaphore:
            # ── method / position 필터 ────────────────────────────────────
            allowed_methods   = [m.upper() for m in template.get("definition", {}).get("method", ["GET", "POST"])]
            allowed_positions = template.get("definition", {}).get("position", ["query", "body", "form_field"])

            if point["method"] not in allowed_methods:
                return []
            if point["position"] not in allowed_positions:
                # JSON·GraphQL 포인트는 position 무관하게 허용
                if point.get("content_type") not in ("json", "graphql"):
                    return []

            # ── 페이로드 준비 ─────────────────────────────────────────────
            all_payloads  = template_loader.get_all_payloads(template)
            sorted_payloads = self._sort_by_priority(
                all_payloads,
                priority_groups=point.get("param_hints", {}),  # 파라미터 단위 정렬은 아래에서
            )

            matchers  = template_loader.compile_matchers(template)
            condition = template.get("matchers_condition", "or")
            waf       = point.get("waf_detected", False)
            max_pld   = point.get("max_payloads", 30)
            ct        = point.get("content_type", "html")
            vuln_type = template.get("id", "").split("-")[0]   # "ssti", "sqli", "xss"

            findings: list[dict] = []

            async with HttpClient() as client:
                for param in point["params"]:
                    # 파라미터별 priority_groups
                    hint = point.get("param_hints", {}).get(param, {})
                    pg   = hint.get("priority_groups", [])

                    param_payloads = self._sort_by_priority(sorted_payloads, pg)[:max_pld]

                    # Mutator로 변종 생성
                    mutated_payloads = self._mutator.mutate_all(
                        param_payloads, vuln_type=vuln_type, waf_detected=waf
                    )

                    tried = 0
                    for pld in mutated_payloads:
                        if tried >= max_pld:
                            break

                        resp = await self._inject(client, point, param, pld["payload"], ct)
                        body = resp.get("body", "")
                        tried += 1

                        matched = self._match(body, matchers, condition)
                        if matched:
                            evidence = self._extract_evidence(body, matched[0])
                            findings.append({
                                "template_id":   template["id"],
                                "vuln_name":     template["info"]["name"],
                                "severity":      template["info"]["severity"],
                                "matched_at":    resp.get("url", point["url"]),
                                "payload":       pld["payload"],
                                "payload_group": pld["group"],
                                "matcher_name":  matched[0]["name"],
                                "evidence":      evidence,
                                "strategy":      pld.get("strategy", "identity"),   # [신규]
                                "content_type":  ct,                                # [신규]
                                "original_payload": pld.get("original_payload", pld["payload"]),
                            })
                            logger.warning(
                                f"[Auditor] FOUND {template['id']} @ {point['url']} "
                                f"param={param} payload={pld['payload']!r} "
                                f"strategy={pld.get('strategy','identity')}"
                            )
                            break   # 첫 매칭 후 다음 파라미터로

            return findings

    # ── 주입 분기 ─────────────────────────────────────────────────────────────

    async def _inject(
        self,
        client: HttpClient,
        point: dict,
        param: str,
        payload: str,
        content_type: str,
    ) -> dict:
        """content_type에 따라 GET/POST-form/POST-JSON/GraphQL 분기."""
        url    = point["url"]
        method = point["method"]

        # ── GraphQL ──────────────────────────────────────────────────────
        if content_type == "graphql":
            gql_query = _GQL_QUERY_TEMPLATES.get(param, _GQL_QUERY_TEMPLATES["_default"])
            # _default 쿼리는 변수명이 "value"이므로 param 으로 교체
            if param not in _GQL_QUERY_TEMPLATES:
                gql_query = gql_query.replace("$value", f"${param}").replace("input: $value", f"{param}: ${param}")
            return await client.post_graphql(url, query=gql_query, variables={param: payload})

        # ── JSON 바디 ─────────────────────────────────────────────────────
        if content_type == "json" and method == "POST":
            body = {p: "test" for p in point.get("params", [])}
            body[param] = payload
            return await client.post_json(url, body)

        # ── 쿼리스트링 (GET) ──────────────────────────────────────────────
        if point["position"] == "query" or method == "GET":
            parsed   = urlparse(url)
            qs       = parse_qs(parsed.query)
            qs[param] = [payload]
            new_query = urlencode({k: v[0] for k, v in qs.items()})
            return await client.get(urlunparse(parsed._replace(query=new_query)))

        # ── POST form ────────────────────────────────────────────────────
        if point["position"] in ("body", "form_field"):
            data          = {p: "test" for p in point.get("params", [])}
            data[param]   = payload
            return await client.post(url, data=data)

        return {"status": 0, "body": "", "headers": {}, "url": url, "content_type": ""}

    # ── 매칭 헬퍼 ─────────────────────────────────────────────────────────────

    def _match(self, body: str, matchers: list[dict], condition: str) -> list[dict]:
        matched = [m for m in matchers if any(p.search(body) for p in m["patterns"])]
        if condition == "and":
            return matched if len(matched) == len(matchers) else []
        return matched[:1] if matched else []

    def _extract_evidence(self, body: str, matcher: dict) -> str:
        for pattern in matcher["patterns"]:
            m = pattern.search(body)
            if m:
                start = max(0, m.start() - 80)
                end   = min(len(body), m.end() + 80)
                return f"...{body[start:end]}..."
        return ""

    # ── 페이로드 정렬 ─────────────────────────────────────────────────────────

    @staticmethod
    def _sort_by_priority(payloads: list[dict], priority_groups: list[str]) -> list[dict]:
        """
        priority_groups 에 속한 payload를 앞으로 이동.
        priority_groups 가 비어있으면 원본 순서 유지.
        """
        if not priority_groups:
            return payloads

        priority_set = set(priority_groups)
        high = [p for p in payloads if p.get("group") in priority_set]
        rest = [p for p in payloads if p.get("group") not in priority_set]
        return high + rest