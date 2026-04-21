"""
core/injector.py — position에 따라 페이로드를 HTTP 요청에 삽입

지원 position:
  query / body / form_field / cookie / header / path

새 position 추가 시 _INJECTORS 딕셔너리에 함수 하나만 등록하면 됨.
"""
from __future__ import annotations

import logging
from typing import Any, Callable
from urllib.parse import quote, urlencode

import requests

from models import ScanTarget
from validator import sanitize_header_value

logger = logging.getLogger("Injector")

_InjectorFn = Callable[
    [str, str, str, dict[str, Any], dict[str, str]],
    requests.PreparedRequest,
]


# ──────────────────────────────────────────────
# 내부 주입 함수
# fn(url, param, payload, extra, headers) → PreparedRequest
# ──────────────────────────────────────────────

def _inject_query(url, param, payload, extra, headers):
    params   = extra.copy()
    params[param] = payload
    base_url = url.split("?")[0]
    full_url = f"{base_url}?{urlencode(params)}"
    return requests.Request(method="GET", url=full_url, headers=headers).prepare()


def _inject_body(url, param, payload, extra, headers):
    data = extra.copy()
    data[param] = payload
    hdrs = headers.copy()
    hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    return requests.Request(method="POST", url=url, data=data, headers=hdrs).prepare()


# form_field는 body와 동일하게 처리 (method는 build_request에서 덮어씀)
_inject_form_field = _inject_body


def _inject_cookie(url, param, payload, extra, headers):
    cookies = {**extra, param: payload}
    return requests.Request(method="GET", url=url, cookies=cookies, headers=headers).prepare()


def _inject_header(url, param, payload, extra, headers):
    safe_payload = sanitize_header_value(payload)
    hdrs = {**headers, param: safe_payload}
    return requests.Request(method="GET", url=url, headers=hdrs).prepare()


def _inject_path(url, param, payload, extra, headers):
    """URL 경로 내 {param} 플레이스홀더를 페이로드로 치환."""
    injected_url = url.replace(f"{{{param}}}", quote(payload, safe=""))
    return requests.Request(method="GET", url=injected_url, headers=headers).prepare()


_INJECTORS: dict[str, _InjectorFn] = {
    "query":      _inject_query,
    "body":       _inject_body,
    "form_field": _inject_form_field,
    "cookie":     _inject_cookie,
    "header":     _inject_header,
    "path":       _inject_path,
}


# ──────────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────────

def build_request(
    target:          ScanTarget,
    payload:         str,
    method_override: str | None     = None,
    extra_headers:   dict[str, str] = {},
) -> requests.PreparedRequest:
    """
    ScanTarget + 페이로드 → PreparedRequest 생성.

    Parameters
    ----------
    target          : 주입 대상
    payload         : 삽입할 페이로드
    method_override : 강제 메서드 지정
    extra_headers   : 템플릿 레벨 헤더 추가
    """
    fn = _INJECTORS.get(target.position)
    if fn is None:
        raise ValueError(
            f"지원하지 않는 주입 위치: {target.position!r}. "
            f"지원 목록: {list(_INJECTORS)}"
        )

    prepared = fn(
        target.url,
        target.param,
        payload,
        target.extra,
        dict(extra_headers),
    )

    method = (method_override or target.method).upper()
    prepared.method = method
    return prepared
