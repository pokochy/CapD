"""
api/scan.py
────────────
스캔 요청 접수 및 상태 조회 라우터.

POST /api/scan         — 새 스캔 작업 생성 및 백그라운드 실행
GET  /api/scan/{id}   — 특정 스캔 상태 + 결과 조회
GET  /api/scan        — 전체 스캔 목록 (최신순)
DELETE /api/scan/{id} — 스캔 작업 삭제
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.models.database import get_db
from backend.models.schemas import (
    ScanJob,
    ScanJobOut,
    ScanJobSummary,
    ScanRequest,
    ScanResult,
    ScanStatus,
)
from backend.worker.tasks import run_scan

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("", response_model=ScanJobOut, status_code=202)
async def create_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """새 스캔 작업을 생성하고 백그라운드에서 파이프라인을 실행."""
    job = ScanJob(
        id=str(uuid.uuid4()),
        target_url=payload.target_url,
        status=ScanStatus.PENDING,
        templates=",".join(payload.templates) if payload.templates else None,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # 백그라운드 비동기 태스크 등록
    background_tasks.add_task(
        run_scan,
        job_id=job.id,
        target_url=payload.target_url,
        template_ids=payload.templates,
    )

    return job


@router.get("", response_model=list[ScanJobSummary])
async def list_scans(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """전체 스캔 목록 반환 (최신순, 결과 카운트 포함)."""
    stmt = (
        select(
            ScanJob,
            func.count(ScanResult.id).label("result_count"),
        )
        .outerjoin(ScanResult, ScanResult.job_id == ScanJob.id)
        .group_by(ScanJob.id)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).all()

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


@router.get("/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: str, db: AsyncSession = Depends(get_db)):
    """특정 스캔의 상태와 발견된 취약점 상세 반환."""
    stmt = (
        select(ScanJob)
        .where(ScanJob.id == job_id)
        .options(selectinload(ScanJob.results))
    )
    job = (await db.execute(stmt)).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.delete("/{job_id}", status_code=204)
async def delete_scan(job_id: str, db: AsyncSession = Depends(get_db)):
    """스캔 작업 및 연관 결과 삭제."""
    stmt = select(ScanJob).where(ScanJob.id == job_id)
    job = (await db.execute(stmt)).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    await db.delete(job)
    await db.commit()
