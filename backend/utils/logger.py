"""
utils/logger.py
───────────────
공통 로깅 설정. .env의 LOG_LEVEL, LOG_FILE을 읽어 콘솔·파일 동시 출력.
"""

import logging
import os
import sys
from pathlib import Path


def get_logger(name: str) -> logging.Logger:
    """이름 기반 로거 반환. 최초 호출 시 핸들러 등록."""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)
    logger.setLevel(level)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 콘솔 핸들러
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # 파일 핸들러 (LOG_FILE 설정 시)
    log_file = os.getenv("LOG_FILE")
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    return logger
