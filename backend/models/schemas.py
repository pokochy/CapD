"""
models/schemas.py
──────────────────
SQLAlchemy ORM 테이블 정의 + Pydantic 요청/응답 스키마.

테이블:
  - scan_jobs   : 스캔 작업 메타데이터 (URL, 상태, 타임스탬프)
  - scan_results: 개별 취약점 발견 결과
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.database import Base


# ── Enum ─────────────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── ORM Models ────────────────────────────────────────────────────────────────

class ScanJob(Base):
    """스캔 작업 단위."""
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING)
    templates: Mapped[str | None] = mapped_column(Text, nullable=True)   # 쉼표 구분 템플릿 ID
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    results: Mapped[list["ScanResult"]] = relationship(
        "ScanResult", back_populates="job", cascade="all, delete-orphan"
    )


class ScanResult(Base):
    """개별 취약점 발견 결과."""
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    template_id: Mapped[str] = mapped_column(String(100))        # e.g. "ssti-basic"
    vuln_name: Mapped[str] = mapped_column(Text)                 # e.g. "Server-Side Template Injection"
    severity: Mapped[str] = mapped_column(String(20))
    matched_at: Mapped[str] = mapped_column(Text)                # 취약한 URL
    payload: Mapped[str] = mapped_column(Text)                   # 사용된 페이로드
    payload_group: Mapped[str | None] = mapped_column(Text)      # 공격 방식 그룹
    matcher_name: Mapped[str | None] = mapped_column(Text)       # 매칭된 matcher 이름
    evidence: Mapped[str | None] = mapped_column(Text)           # 응답 스니펫
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # 확장 필드
    discovered_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="results")


# ── Pydantic Schemas (API 입출력) ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    """POST /api/scan 요청 바디."""
    target_url: str
    templates: list[str] | None = None  # None이면 전체 템플릿 사용

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class ScanResultOut(BaseModel):
    """개별 취약점 결과 응답."""
    id: str
    template_id: str
    vuln_name: str
    severity: str
    matched_at: str
    payload: str
    payload_group: str | None
    matcher_name: str | None
    evidence: str | None
    discovered_at: datetime

    class Config:
        from_attributes = True


class ScanJobOut(BaseModel):
    """스캔 작업 응답 (결과 포함)."""
    id: str
    target_url: str
    status: str
    templates: str | None
    created_at: datetime
    updated_at: datetime
    error_message: str | None
    results: list[ScanResultOut] = []

    class Config:
        from_attributes = True


class ScanJobSummary(BaseModel):
    """스캔 목록 조회용 요약 (results 제외)."""
    id: str
    target_url: str
    status: str
    created_at: datetime
    result_count: int = 0

    class Config:
        from_attributes = True
