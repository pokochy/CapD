"""
api/reports.py
───────────────
보고서 조회 전용 라우터.

GET /api/reports           — 완료된 스캔 목록 (취약점 수 포함)
GET /api/reports/{job_id}  — 특정 스캔의 상세 보고서
GET /api/reports/templates — 사용 가능한 탐지 템플릿 목록
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.engine.templates.loader import template_loader
from backend.models.database import get_db
from backend.models.schemas import ScanJob, ScanJobOut, ScanJobSummary, ScanResult, ScanStatus

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("", response_model=list[ScanJobSummary])
async def list_reports(
    severity: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    완료된 스캔 보고서 목록.
    severity 필터: critical | high | medium | low
    """
    base = (
        select(
            ScanJob,
            func.count(ScanResult.id).label("result_count"),
        )
        .where(ScanJob.status == ScanStatus.COMPLETED)
        .outerjoin(ScanResult, ScanResult.job_id == ScanJob.id)
        .group_by(ScanJob.id)
        .order_by(ScanJob.created_at.desc())
    )

    if severity:
        base = base.where(ScanResult.severity == severity.lower())

    rows = (await db.execute(base)).all()
    return [
        ScanJobSummary(
            id=row[0].id,
            target_url=row[0].target_url,
            status=row[0].status,
            created_at=row[0].created_at,
            result_count=row[1],
        )
        for row in rows
    ]


@router.get("/templates")
async def list_templates():
    """사용 가능한 탐지 템플릿 메타데이터 목록."""
    templates = template_loader.load_all()
    return [
        {
            "id": t.get("id"),
            "name": t.get("info", {}).get("name"),
            "severity": t.get("info", {}).get("severity"),
            "description": t.get("info", {}).get("description", "").strip(),
            "tags": t.get("info", {}).get("tags", []),
            "payload_groups": [
                {"group": g.get("group"), "engine": g.get("engine")}
                for g in t.get("payload_groups", [])
            ],
        }
        for t in templates
    ]


@router.get("/{job_id}", response_model=ScanJobOut)
async def get_report(job_id: str, db: AsyncSession = Depends(get_db)):
    """특정 스캔의 상세 보고서 (완료 여부 무관)."""
    stmt = (
        select(ScanJob)
        .where(ScanJob.id == job_id)
        .options(selectinload(ScanJob.results))
    )
    job = (await db.execute(stmt)).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Report not found")
    return job
