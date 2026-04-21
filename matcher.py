"""
core/matcher.py — 템플릿 matchers[] 평가

지원 타입: word / time / status / regex / size / header

새 타입 추가 시 _EVALUATORS 딕셔너리에 함수 하나만 등록.
"""
from __future__ import annotations

import logging
import re
from typing import Callable

import requests

from core.models import MatcherResult
from core.template_loader import MatcherDef, ScanTemplate

logger = logging.getLogger("Matcher")

_EvalFn = Callable[
    [MatcherDef, "requests.Response | None", float],
    MatcherResult,
]


# ──────────────────────────────────────────────
# 개별 평가 함수
# ──────────────────────────────────────────────

def _eval_word(defn: MatcherDef, resp: "requests.Response | None", _: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="word", detail=[])
    body  = resp.text
    words = defn.data.get("words", [])
    found = [w for w in words if w in body]
    hit   = (len(found) == len(words)) if defn.condition == "and" else bool(found)
    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="word", detail=found)


def _eval_time(defn: MatcherDef, _: "requests.Response | None", elapsed: float) -> MatcherResult:
    delay = float(defn.data.get("delay", 5))
    hit   = elapsed >= delay
    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="time", detail=[f"{elapsed:.2f}s >= {delay}s"])


def _eval_status(defn: MatcherDef, resp: "requests.Response | None", _: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="status", detail=[])
    codes  = [int(c) for c in defn.data.get("status", [])]
    actual = resp.status_code
    hit    = (all(actual == c for c in codes)) if defn.condition == "and" else (actual in codes)
    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="status", detail=[str(actual)])


def _eval_regex(defn: MatcherDef, resp: "requests.Response | None", _: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="regex", detail=[])
    body     = resp.text
    patterns = defn.data.get("regex", [])
    matched  = []
    for p in patterns:
        try:
            if re.search(p, body):
                matched.append(p)
        except re.error as exc:
            logger.warning("정규식 오류 [%s]: %s", p, exc)
    hit = (len(matched) == len(patterns)) if defn.condition == "and" else bool(matched)
    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="regex", detail=matched)


def _eval_size(defn: MatcherDef, resp: "requests.Response | None", _: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="size", detail=[])
    body_len = len(resp.content)
    sizes    = [int(s) for s in defn.data.get("size", [])]
    hit      = (all(body_len == s for s in sizes)) if defn.condition == "and" else (body_len in sizes)
    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="size", detail=[str(body_len)])


def _eval_header(defn: MatcherDef, resp: "requests.Response | None", _: float) -> MatcherResult:
    """응답 헤더 키/값 검사."""
    if resp is None:
        return MatcherResult(hit=False, mtype="header", detail=[])

    header_name  = defn.data.get("name", "")
    header_value = defn.data.get("value", "")
    actual       = resp.headers.get(header_name, "")

    if header_value:
        hit = header_value.lower() in actual.lower()
    else:
        hit = header_name in resp.headers

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="header", detail=[f"{header_name}: {actual}"])


_EVALUATORS: dict[str, _EvalFn] = {
    "word":   _eval_word,
    "time":   _eval_time,
    "status": _eval_status,
    "regex":  _eval_regex,
    "size":   _eval_size,
    "header": _eval_header,
}


# ──────────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────────

def evaluate_matchers(
    template: ScanTemplate,
    response: "requests.Response | None",
    elapsed:  float,
) -> tuple[bool, list[MatcherResult]]:
    """
    템플릿의 모든 matchers를 평가하고
    (전체 판정 bool, 개별 결과 리스트)를 반환.
    """
    results: list[MatcherResult] = []

    for defn in template.matchers:
        fn = _EVALUATORS.get(defn.type)
        if fn is None:
            logger.warning("알 수 없는 matcher 타입: %r — 건너뜀", defn.type)
            continue
        results.append(fn(defn, response, elapsed))

    if not results:
        return False, []

    overall = (
        all(r.hit for r in results)
        if template.matchers_condition == "and"
        else any(r.hit for r in results)
    )
    return overall, results
