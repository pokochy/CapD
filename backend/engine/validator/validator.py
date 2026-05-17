"""
engine/validator/validator.py
──────────────────────────────
5단계: Auditor가 반환한 후보 결과에서 오탐(False Positive)을 제거.
- 원본 응답(페이로드 없음)과 비교하여 페이로드 반사 여부 재확인
- 동일 URL+payload 중복 제거
"""

from __future__ import annotations

from utils.http_client import HttpClient
from utils.logger import get_logger
from engine.templates.loader import template_loader

logger = get_logger("validator")


class Validator:
    """오탐 필터링 및 최종 결과 정제."""

    async def run(self, findings: list[dict]) -> list[dict]:
        """
        findings: Auditor.run()의 반환값
        반환: 검증된 최종 결과 리스트
        """
        if not findings:
            return []

        # 1. 중복 제거 (URL + template_id + payload 조합)
        deduped = self._deduplicate(findings)
        logger.info(f"[Validator] After dedup: {len(findings)} → {len(deduped)}")

        # 2. 원본 응답 대조 검증
        validated = await self._verify_against_baseline(deduped)
        logger.info(f"[Validator] After verification: {len(deduped)} → {len(validated)}")

        return validated

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """동일한 URL + 취약점 + 페이로드 조합 중복 제거."""
        seen: set[tuple] = set()
        result: list[dict] = []
        for f in findings:
            key = (f["matched_at"], f["template_id"], f["payload"])
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result

    async def _verify_against_baseline(self, findings: list[dict]) -> list[dict]:
        """
        원본 URL(페이로드 없이)을 요청하여 이미 49 등이 포함되어 있는지 확인.
        원본에도 매칭된다면 오탐으로 제거.
        """
        validated: list[dict] = []

        # 이미 로드된 템플릿의 matcher 캐시
        matcher_cache: dict[str, list[dict]] = {}

        async with HttpClient() as client:
            for finding in findings:
                template_id = finding["template_id"]

                # matcher 컴파일 캐시
                if template_id not in matcher_cache:
                    tmpl = template_loader.load_by_id(template_id)
                    if tmpl:
                        matcher_cache[template_id] = template_loader.compile_matchers(tmpl)
                    else:
                        matcher_cache[template_id] = []

                matchers = matcher_cache[template_id]

                # 원본 URL (쿼리스트링 제거)
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(finding["matched_at"])
                baseline_url = urlunparse(parsed._replace(query=""))

                baseline_resp = await client.get(baseline_url)
                baseline_body = baseline_resp.get("body", "")

                # 원본에서도 매칭되면 오탐
                already_present = any(
                    any(p.search(baseline_body) for p in m["patterns"])
                    for m in matchers
                )

                if already_present:
                    logger.debug(
                        f"[Validator] FP removed: {finding['template_id']} @ {finding['matched_at']}"
                    )
                    finding["_fp_reason"] = "baseline_match"
                else:
                    validated.append(finding)

        return validated
