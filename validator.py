"""
core/validator.py — 사용자 입력 검증 및 안전성 검사
"""
from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger("Validator")

# 내부 네트워크 대역 (SSRF 방지)
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# 허용 URL 스킴
_ALLOWED_SCHEMES = {"http", "https"}


class ValidationError(Exception):
    """입력 검증 실패 예외."""


def validate_url(url: str, allow_private: bool = False) -> str:
    """
    URL 유효성 검증.

    - 스킴(http/https)만 허용
    - 내부망 접근 차단 (allow_private=True로 우회 가능)
    - 빈 URL 거부
    """
    if not url or not url.strip():
        raise ValidationError("URL이 비어 있습니다.")

    url = url.strip()

    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValidationError(
            f"허용되지 않는 URL 스킴: {parsed.scheme!r}. "
            f"허용: {_ALLOWED_SCHEMES}"
        )

    if not parsed.netloc:
        raise ValidationError(f"URL에 호스트가 없습니다: {url}")

    hostname = parsed.hostname or ""

    # IP 주소인 경우 내부망 차단
    if not allow_private:
        try:
            ip = ipaddress.ip_address(hostname)
            for net in _PRIVATE_RANGES:
                if ip in net:
                    raise ValidationError(
                        f"내부 IP 주소에 대한 요청은 허용되지 않습니다: {hostname}"
                    )
        except ValueError:
            pass  # 도메인명 → 통과

    return url


def validate_rate_limit(requests_per_second: float) -> float:
    """초당 요청 수 범위 검증 (0.1 ~ 50)."""
    if not (0.1 <= requests_per_second <= 50):
        raise ValidationError(
            f"초당 요청 수는 0.1~50 범위여야 합니다: {requests_per_second}"
        )
    return requests_per_second


def validate_timeout(timeout: float) -> float:
    """타임아웃 범위 검증 (1 ~ 120초)."""
    if not (1.0 <= timeout <= 120.0):
        raise ValidationError(
            f"타임아웃은 1~120초 범위여야 합니다: {timeout}"
        )
    return timeout


def sanitize_header_value(value: str) -> str:
    """헤더 값에서 개행 문자 제거 (헤더 인젝션 방지)."""
    cleaned = re.sub(r"[\r\n]", "", value)
    if cleaned != value:
        logger.warning("헤더 값에서 개행 문자가 제거되었습니다.")
    return cleaned
