"""
models/database.py
──────────────────
SQLite (aiosqlite) 기반 경량 DB 설정.
앱 시작 시 테이블 자동 생성. 별도 서버 불필요.
"""

from __future__ import annotations

import os

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

# .env에서 DB URL 읽기 (기본값: 로컬 파일 sqlite)
_RAW_URL = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")
# SQLAlchemy async 드라이버로 변환 (sqlite → sqlite+aiosqlite)
DATABASE_URL = _RAW_URL.replace("sqlite:///", "sqlite+aiosqlite:///")


class Base(DeclarativeBase):
    """모든 ORM 모델의 베이스 클래스."""
    pass


# 비동기 엔진 생성
engine = create_async_engine(
    DATABASE_URL,
    echo=os.getenv("DEBUG", "false").lower() == "true",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """앱 시작 시 호출 — 테이블이 없으면 자동 생성."""
    from models import schemas  # 순환 참조 방지용 지연 임포트
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI Depends용 DB 세션 제너레이터."""
    async with AsyncSessionLocal() as session:
        yield session
