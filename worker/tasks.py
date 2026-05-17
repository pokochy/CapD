"""
worker/tasks.py
────────────────
스캔 파이프라인 오케스트레이터.
[업그레이드 v2] Contextualizer 단계 삽입.

파이프라인 순서
───────────────
  1. Fingerprinter  — 기술 스택·WAF 탐지
  2. Crawler        — 입력 포인트 수집
  3. Contextualizer — 포인트별 최적 컨텍스트 부여  ← [신규]
  4. Auditor        — 페이로드 주입 (JSON·GraphQL 포함)
  5. Validator      — 오탐 제거
  6. DB 저장

변경 내역
──────────
- Crawler 결과를 Contextualizer에 통과시켜 enriched_points 생성
- Crawler 응답 Content-Type 메타를 Contextualizer에 전달
- Auditor는 enriched_points를 직접 소비
- ScanResult.extra 에 strategy·original_payload·content_type 저장
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse, parse_qs

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from engine.profiler.fingerprint import Fingerprinter
from engine.crawler.crawler import Crawler
from engine.contextualizer.contextualizer import Contextualizer
from engine.auditor.auditor import Auditor
from engine.validator.validator import Validator
from models.database import AsyncSessionLocal
from models.schemas import ScanJob, ScanResult, ScanStatus
from utils.logger import get_logger

logger = get_logger("worker")


async def run_scan(job_id: str, target_url: str, template_ids: list[str] | None) -> None:
    """
    스캔 파이프라인 메인 태스크.
    FastAPI BackgroundTasks에서 호출된다.
    """
    logger.info(f"[Worker] Scan started: job_id={job_id} url={target_url}")

    async with AsyncSessionLocal() as db:
        await _update_status(db, job_id, ScanStatus.RUNNING)

        try:
            # ── 1. Fingerprinting ──────────────────────────────────────────
            profiler = Fingerprinter()
            profile = await profiler.run(target_url)
            logger.info(
                f"[Worker] Profile: tech={profile.get('technologies')} "
                f"waf={profile.get('waf')} waf_detected={profile.get('waf_detected')}"
            )
            if profile.get("waf_detected"):
                logger.warning(
                    f"[Worker] WAF detected: {profile['waf']} — "
                    "Mutator will generate bypass variants automatically"
                )
            # 핑거프린트 결과 DB 저장
            await db.execute(
                update(ScanJob).where(ScanJob.id == job_id).values(fingerprint_result=profile)
            )
            await db.commit()

            # ── 2. Crawling ────────────────────────────────────────────────
            crawler = Crawler()
            input_points, response_meta = await _crawl_with_meta(crawler, target_url)

            # 입력 포인트 없으면 타깃 URL 직접 테스트
            if not input_points:
                logger.info("[Worker] No input points found; testing target URL directly")
                parsed = urlparse(target_url)
                if parsed.query:
                    input_points.append({
                        "url": target_url,
                        "method": "GET",
                        "position": "query",
                        "params": list(parse_qs(parsed.query).keys()),
                    })

            logger.info(f"[Worker] Input points: {len(input_points)}")

            # ── 3. Contextualizer (신규) ───────────────────────────────────
            contextualizer = Contextualizer()
            enriched_points = contextualizer.run(
                input_points=input_points,
                profile=profile,
                response_meta=response_meta,
            )
            _log_enriched_summary(enriched_points)

            # ── 4. Auditing ────────────────────────────────────────────────
            auditor = Auditor()
            raw_findings = await auditor.run(enriched_points, template_ids)
            logger.info(f"[Worker] Raw findings: {len(raw_findings)}")

            # ── 5. Validation ──────────────────────────────────────────────
            validator = Validator()
            findings = await validator.run(raw_findings)
            logger.info(f"[Worker] Confirmed findings: {len(findings)}")

            # ── 6. DB 저장 ─────────────────────────────────────────────────
            for finding in findings:
                db.add(ScanResult(
                    job_id=job_id,
                    template_id=finding["template_id"],
                    vuln_name=finding["vuln_name"],
                    severity=finding["severity"],
                    matched_at=finding["matched_at"],
                    payload=finding["payload"],
                    payload_group=finding.get("payload_group"),
                    matcher_name=finding.get("matcher_name"),
                    evidence=finding.get("evidence"),
                    extra={
                        "strategy":         finding.get("strategy"),
                        "original_payload": finding.get("original_payload"),
                        "content_type":     finding.get("content_type"),
                    },
                ))

            await _update_status(db, job_id, ScanStatus.COMPLETED)
            await db.commit()
            logger.info(f"[Worker] Scan completed: job_id={job_id} findings={len(findings)}")

        except Exception as exc:
            logger.exception(f"[Worker] Scan failed: job_id={job_id} error={exc}")
            await _update_status(db, job_id, ScanStatus.FAILED, error=str(exc))
            await db.commit()


# ── 헬퍼 ──────────────────────────────────────────────────────────────────────

async def _crawl_with_meta(
    crawler: Crawler,
    target_url: str,
) -> tuple[list[dict], list[dict]]:
    """
    Crawler를 실행하고 응답 Content-Type 메타를 함께 반환한다.
    Crawler.run()이 tuple(points, meta)을 반환하면 언패킹,
    list만 반환하면 (list, []) 로 변환.
    """
    result = await crawler.run(target_url)
    if isinstance(result, tuple) and len(result) == 2:
        return result[0], result[1]
    return result, []


async def _update_status(
    db: AsyncSession,
    job_id: str,
    status: ScanStatus,
    error: str | None = None,
) -> None:
    stmt = (
        update(ScanJob)
        .where(ScanJob.id == job_id)
        .values(
            status=status,
            updated_at=datetime.utcnow(),
            error_message=error,
        )
    )
    await db.execute(stmt)


def _log_enriched_summary(points: list[dict]) -> None:
    json_ct    = sum(1 for p in points if p.get("content_type") == "json")
    graphql_ct = sum(1 for p in points if p.get("content_type") == "graphql")
    waf_ct     = sum(1 for p in points if p.get("waf_detected"))
    logger.info(
        f"[Worker] Enriched: total={len(points)} "
        f"json={json_ct} graphql={graphql_ct} waf_flagged={waf_ct}"
    )