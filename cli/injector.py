"""
core/injector.py

position(query / body / cookie / header / path / form_field) 에 따라
페이로드를 HTTP 요청에 삽입하고 requests.PreparedRequest 를 반환한다.
"""

from __future__ import annotations

from typing import Callable, Any
from urllib.parse import urlencode, quote
import requests

from core.models import ScanTarget, Position


_InjectorFn = Callable[
    [str, str, str, dict[str, Any], dict[str, str]],
    requests.PreparedRequest,
]


def _inject_body(url, param, payload, extra, headers):
    data = extra.copy()
    data[param] = payload

    headers = headers.copy()
    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = requests.Request(method="POST", url=url, data=data, headers=headers)
    return req.prepare()


def _inject_query(url, param, payload, extra, headers):
    params = extra.copy()
    params[param] = payload

    base_url = url.split("?")[0]
    full_url = f"{base_url}?{urlencode(params)}"

    req = requests.Request(method="GET", url=full_url, headers=headers)
    return req.prepare()


_inject_form_field = _inject_body


def _inject_cookie(url, param, payload, extra, headers) -> requests.PreparedRequest:
    cookies = {**extra, param: payload}
    req     = requests.Request(method="GET", url=url, cookies=cookies, headers=headers)
    return req.prepare()


def _inject_header(url, param, payload, extra, headers) -> requests.PreparedRequest:
    hdrs = {**headers, param: payload}
    req  = requests.Request(method="GET", url=url, headers=hdrs)
    return req.prepare()


def _inject_path(url, param, payload, extra, headers) -> requests.PreparedRequest:
    injected_url = url.replace(f"{{{param}}}", quote(payload, safe=""))
    req = requests.Request(method="GET", url=injected_url, headers=headers)
    return req.prepare()


_INJECTORS: dict[str, _InjectorFn] = {
    "query":      _inject_query,
    "body":       _inject_body,
    "form_field": _inject_form_field,
    "cookie":     _inject_cookie,
    "header":     _inject_header,
    "path":       _inject_path,
}


def build_request(
    target:          ScanTarget,
    payload:         str,
    method_override: str | None = None,
    extra_headers:   dict[str, str] | None = None,  # [BUG FIX] mutable default {} → None
) -> requests.PreparedRequest:
    """
    ScanTarget + 페이로드 → PreparedRequest.
    """
    # [BUG FIX] None 이면 빈 dict 사용 (mutable default argument 방지)
    if extra_headers is None:
        extra_headers = {}

    position = target.position
    fn = _INJECTORS.get(position)
    if fn is None:
        raise ValueError(
            f"Unsupported injection position: {position!r}. "
            f"Supported: {list(_INJECTORS)}"
        )

    prepared = fn(
        target.url,
        target.param,
        payload,
        target.extra,
        extra_headers,
    )

    method = (method_override or target.method).upper()
    prepared.method = method

    return prepared
