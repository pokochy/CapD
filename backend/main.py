"""
main.py
────────
FastAPI 애플리케이션 엔트리포인트.
- .env 로드
- DB 초기화
- 라우터 등록
- CORS 설정
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# 가장 먼저 .env 로드
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.scan import router as scan_router
from backend.api.reports import router as reports_router
from backend.models.database import init_db
from backend.utils.logger import get_logger

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """앱 시작/종료 시 실행되는 수명 주기 훅."""
    logger.info("Starting Vulnerability Scanner API...")
    await init_db()
    logger.info("Database initialized (SQLite)")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="Vulnerability Scanner API",
    description="SSTI, SQLi, XSS 등 웹 취약점 자동 스캔 백엔드",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ─────────────────────────────────────────────────────────────────────
_origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:3000")
origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 라우터 등록 ───────────────────────────────────────────────────────────────
app.include_router(scan_router)
app.include_router(reports_router)


@app.get("/", tags=["health"])
async def root():
    return {"status": "ok", "service": "vulnerability-scanner", "version": "1.0.0"}


@app.get("/health", tags=["health"])
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("APP_PORT", "8000")),
        reload=os.getenv("APP_ENV", "development") == "development",
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
