"""
core/logger.py — 로깅 초기화 및 설정
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path


def setup_logging(
    level:    str  = "INFO",
    log_file: str  | None = None,
    quiet:    bool = False,
) -> None:
    """
    루트 로거 및 파일 핸들러 초기화.

    Parameters
    ----------
    level    : 로그 레벨 (DEBUG / INFO / WARNING / ERROR)
    log_file : 로그 파일 경로. None이면 파일 저장 안 함.
    quiet    : True이면 콘솔 출력 억제 (파일만 저장).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(numeric_level)

    fmt = logging.Formatter(
        fmt     = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt = "%Y-%m-%d %H:%M:%S",
    )

    # 콘솔 핸들러
    if not quiet:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(numeric_level)
        console.setFormatter(fmt)
        root.addHandler(console)

    # 파일 핸들러
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(numeric_level)
        fh.setFormatter(fmt)
        root.addHandler(fh)
