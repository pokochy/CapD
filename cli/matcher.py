"""
core/matcher.py

템플릿의 matchers[] 를 평가한다.
지원 타입 : word / time / status / regex / size

새로운 타입 추가 시 : _EVALUATORS 딕셔너리에 함수 하나만 등록하면 됨.
"""

from __future__ import annotations

import re
from typing import Callable

import requests

from core.models import MatcherResult
from core.template_loader import MatcherDef, ScanTemplate


_EvalFn = Callable[
    [MatcherDef, requests.Response | None, float],
    MatcherResult,
]


def _eval_word(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="word", detail=[])

    # [BUG FIX] 대소문자 구분 없이 검색 — SQL syntax / sql syntax 모두 탐지
    body  = resp.text.lower()
    words = defn.data.get("words", [])

    if defn.condition == "and":
        found = [w for w in words if w.lower() in body]
        hit   = len(found) == len(words)
    else:  # or
        found = [w for w in words if w.lower() in body]
        hit   = len(found) > 0

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="word", detail=found)


def _eval_time(defn: MatcherDef, _resp: requests.Response | None, elapsed: float) -> MatcherResult:
    delay = float(defn.data.get("delay", 5))
    hit   = elapsed >= delay
    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="time", detail=[f"{elapsed:.2f}s >= {delay}s"])


def _eval_status(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="status", detail=[])

    codes  = [int(c) for c in defn.data.get("status", [])]
    actual = resp.status_code

    if defn.condition == "and":
        hit = all(actual == c for c in codes)
    else:
        hit = actual in codes

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="status", detail=[str(actual)])


def _eval_regex(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="regex", detail=[])

    body     = resp.text
    patterns = defn.data.get("regex", [])
    matched  = [p for p in patterns if re.search(p, body)]

    if defn.condition == "and":
        hit = len(matched) == len(patterns)
    else:
        hit = len(matched) > 0

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="regex", detail=matched)


def _eval_size(defn: MatcherDef, resp: requests.Response | None, _elapsed: float) -> MatcherResult:
    if resp is None:
        return MatcherResult(hit=False, mtype="size", detail=[])

    body_len = len(resp.content)
    sizes    = [int(s) for s in defn.data.get("size", [])]

    if defn.condition == "and":
        hit = all(body_len == s for s in sizes)
    else:
        hit = body_len in sizes

    if defn.negate:
        hit = not hit
    return MatcherResult(hit=hit, mtype="size", detail=[str(body_len)])


_EVALUATORS: dict[str, _EvalFn] = {
    "word":   _eval_word,
    "time":   _eval_time,
    "status": _eval_status,
    "regex":  _eval_regex,
    "size":   _eval_size,
}


def evaluate_matchers(
    template: ScanTemplate,
    response: requests.Response | None,
    elapsed:  float,
) -> tuple[bool, list[MatcherResult]]:
    """
    템플릿의 모든 matchers를 평가하고
    (전체 판정 bool, 개별 결과 리스트) 를 반환.
    """
    results: list[MatcherResult] = []

    for defn in template.matchers:
        fn = _EVALUATORS.get(defn.type)
        if fn is None:
            print(f"[WARN] Unknown matcher type: {defn.type!r} — skipped")
            continue
        results.append(fn(defn, response, elapsed))

    if not results:
        return False, []

    if template.matchers_condition == "and":
        overall = all(r.hit for r in results)
    else:  # or
        overall = any(r.hit for r in results)

    return overall, results
