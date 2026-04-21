"""
core/models.py — 파이프라인 전체 공유 데이터 모델
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Method   = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
Position = Literal["query", "body", "cookie", "header", "path", "form_field"]


# ──────────────────────────────────────────────
# 크롤러 → 분석기 모델
# ──────────────────────────────────────────────

@dataclass
class FieldDef:
    """HTML 폼 입력 필드 하나."""
    name:       str
    field_type: str
    value:      str       = ""
    options:    list[str] = field(default_factory=list)


@dataclass
class FormDef:
    """HTML 폼 하나."""
    action:   str
    method:   Method
    fields:   list[FieldDef]
    found_on: str = ""


@dataclass
class CrawledPage:
    """크롤러가 반환하는 페이지 단위."""
    url:          str
    query_params: dict[str, str] = field(default_factory=dict)
    forms:        list[FormDef]  = field(default_factory=list)
    headers:      dict[str, str] = field(default_factory=dict)
    cookies:      dict[str, str] = field(default_factory=dict)


# ──────────────────────────────────────────────
# 분석기 → 엔진 모델
# ──────────────────────────────────────────────

@dataclass
class ScanTarget:
    """Analyzer가 엔진으로 넘기는 주입 단위."""
    url:      str
    method:   Method
    position: Position
    param:    str
    extra:    dict[str, Any] = field(default_factory=dict)
    found_on: str            = ""

    @property
    def original(self) -> str:
        """주입 대상 파라미터의 원본값."""
        return str(self.extra.get(self.param, ""))


# ──────────────────────────────────────────────
# 엔진 → 리포터 모델
# ──────────────────────────────────────────────

@dataclass
class MatcherResult:
    hit:    bool
    mtype:  str
    detail: list[str]


@dataclass
class ScanResult:
    """스캔 결과 단위 (리포트·시각화에 전달)."""
    target:        ScanTarget
    template_id:   str
    template_name: str
    severity:      str
    payload:       str
    matched:       bool
    match_results: list[MatcherResult] = field(default_factory=list)
    elapsed:       float               = 0.0
    status_code:   int                 = 0
    response_body: str                 = ""
    error:         str                 = ""
