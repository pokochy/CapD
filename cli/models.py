"""
models.py — 공통 데이터 모델
모든 모듈이 공유하는 dataclass 정의
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ── 크롤러 모델 ─────────────────────────────────────────

@dataclass
class FormField:
    name: str
    field_type: str          # text | password | hidden | select | textarea …
    value: str = ""
    options: list[str] = field(default_factory=list)


@dataclass
class CrawledForm:
    action: str              # 폼 제출 URL
    method: str              # GET | POST
    fields: list[FormField]
    found_on: str            # 발견된 페이지 URL


@dataclass
class CrawledPage:
    url: str
    status_code: int
    content_type: str
    links: list[str]
    forms: list[CrawledForm]
    query_params: dict[str, str]
    response_headers: dict[str, str]
    depth: int


# ── 스캐너 모델 ─────────────────────────────────────────

@dataclass
class ScanTarget:
    """
    analyzer.py 가 생성하고 engine.py 가 소비하는 주입 지점 표준 포맷.

    position 값:
        "query"      — URL ?param=value
        "body"       — POST form data
        "cookie"     — Cookie 헤더 내 필드
        "header"     — 일반 HTTP 요청 헤더
        "form_field" — 크롤러가 발견한 <form> 필드 (query/body 파생)
        "path"       — URL 경로 내 {{PAYLOAD}} 치환 (레거시)
    """
    position: str
    url: str
    method: str
    name: str                        # 주입 대상 파라미터/헤더 이름
    base_data: dict[str, str] = field(default_factory=dict)   # 나머지 필드 기본값
    found_on: str = ""


@dataclass
class Finding:
    """탐지된 취약점 단건"""
    vulnerability: str
    severity: str
    position: str
    url: str
    method: str
    inject_param: str
    payload: str
    evidence: str                    # 매치된 키워드 or "time-delay" or "status-NNN"
    found_on: str
