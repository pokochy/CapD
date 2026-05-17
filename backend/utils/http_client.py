"""
utils/http_client.py
─────────────────────
aiohttp 기반 비동기 HTTP 클라이언트.
[업그레이드 v2] JSON 바디 주입, GraphQL 쿼리 주입 메서드 추가.
                Content-Type 자동 감지 및 응답 메타 반환 지원.

변경 내역
──────────
- post_json()    : application/json 바디로 페이로드 전송
- post_graphql() : GraphQL variables 필드에 페이로드 주입
- 응답 dict에 "content_type" 필드 추가
- data가 str일 때 bytes 변환 처리 (aiohttp 호환성)
"""

from __future__ import annotations

import asyncio
import json as _json_mod
import os
from typing import Any

import aiohttp
from aiohttp import ClientSession, TCPConnector

from utils.logger import get_logger

logger = get_logger("http_client")

# ── .env 설정 ──────────────────────────────────────────────────────────────────
_TIMEOUT         = int(os.getenv("SCAN_TIMEOUT", "30"))
_VERIFY_SSL      = os.getenv("VERIFY_SSL", "false").lower() == "true"
_USER_AGENT      = os.getenv("USER_AGENT", "Mozilla/5.0 (compatible; VulnScanner/1.0)")
_FOLLOW_REDIRECTS= os.getenv("FOLLOW_REDIRECTS", "true").lower() == "true"
_MAX_REDIRECTS   = int(os.getenv("MAX_REDIRECTS", "5"))
_DELAY           = float(os.getenv("SCAN_DELAY", "0.5"))


class HttpClient:
    """
    스캔 엔진 전용 HTTP 클라이언트.

    지원 요청 유형
    ──────────────
    GET             : 쿼리스트링 파라미터 주입
    POST form       : application/x-www-form-urlencoded
    POST JSON       : application/json 바디       ← [신규]
    POST GraphQL    : {"query":..., "variables":{}} ← [신규]
    """

    def __init__(self) -> None:
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "HttpClient":
        connector = TCPConnector(ssl=_VERIFY_SSL)
        timeout = aiohttp.ClientTimeout(total=_TIMEOUT)
        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    # ── 공개 메서드 ──────────────────────────────────────────────────────────────

    async def get(
        self,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> dict:
        """GET 요청. 응답 바디·상태코드·Content-Type 딕셔너리 반환."""
        return await self._request("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        data: dict | None = None,
        json: dict | None = None,
        headers: dict | None = None,
    ) -> dict:
        """POST form-urlencoded 또는 raw JSON 요청 (기존 인터페이스 유지)."""
        return await self._request("POST", url, data=data, json=json, headers=headers)

    async def post_json(
        self,
        url: str,
        body: dict,
        extra_headers: dict | None = None,
    ) -> dict:
        """
        [신규] application/json 바디로 POST 요청.
        body 딕셔너리를 JSON 직렬화하여 전송한다.

        사용 예:
            resp = await client.post_json(url, {"username": payload, "password": "x"})
        """
        headers = {
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }
        return await self._request(
            "POST",
            url,
            data=_json_dumps(body),   # str → bytes 변환은 _request 내부에서 처리
            headers=headers,
        )

    async def post_graphql(
        self,
        url: str,
        query: str,
        variables: dict | None = None,
        extra_headers: dict | None = None,
    ) -> dict:
        """
        [신규] GraphQL endpoint에 POST 요청.
        variables 딕셔너리 안의 값으로 페이로드가 삽입된다.

        사용 예:
            resp = await client.post_graphql(
                url,
                query='query Search($q: String!) { search(input: $q) { id } }',
                variables={"q": payload},
            )
        """
        gql_body = {"query": query, "variables": variables or {}}
        headers = {
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }
        return await self._request(
            "POST",
            url,
            data=_json_dumps(gql_body),
            headers=headers,
        )

    # ── 내부 구현 ────────────────────────────────────────────────────────────────

    async def _request(self, method: str, url: str, **kwargs: Any) -> dict:
        assert self._session, "HttpClient must be used as async context manager"
        await asyncio.sleep(_DELAY)

        # str 바디를 bytes로 변환 (aiohttp는 str data를 거부함)
        raw_data = kwargs.pop("data", None)
        if isinstance(raw_data, str):
            kwargs["data"] = raw_data.encode("utf-8")
        elif raw_data is not None:
            kwargs["data"] = raw_data

        try:
            async with self._session.request(
                method,
                url,
                allow_redirects=_FOLLOW_REDIRECTS,
                max_redirects=_MAX_REDIRECTS,
                **kwargs,
            ) as resp:
                body = await resp.text(errors="replace")
                content_type = resp.headers.get("Content-Type", "")
                logger.debug(f"{method} {url} → {resp.status} ct={content_type[:40]}")
                return {
                    "status":       resp.status,
                    "body":         body,
                    "headers":      dict(resp.headers),
                    "url":          str(resp.url),
                    "content_type": content_type,  # [신규] 응답 Content-Type
                }
        except asyncio.TimeoutError:
            logger.warning(f"Timeout: {method} {url}")
            return _err(url, "timeout")
        except Exception as exc:
            logger.error(f"Request error {method} {url}: {exc}")
            return _err(url, str(exc))


# ── 유틸 ──────────────────────────────────────────────────────────────────────

def _json_dumps(obj: Any) -> str:
    """JSON 직렬화 (한글 이스케이프 방지)."""
    return _json_mod.dumps(obj, ensure_ascii=False)


def _err(url: str, error: str) -> dict:
    return {"status": 0, "body": "", "headers": {},
            "url": url, "content_type": "", "error": error}