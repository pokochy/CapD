"""
core/engine.py — 비동기 페이로드 삽입 엔진

파이프라인:
  크롤링 → Analyzer(ScanTarget 생성) → ScanEngine.run() → List[ScanResult]

비동기 구조:
  - asyncio + httpx로 동시 요청 처리
  - max_concurrency로 동시 요청 수 제한 (rate limit 준수)
  - semaphore로 무한 요청 방지
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

import httpx

from injector        import build_request
from matcher         import evaluate_matchers
from models          import ScanResult, ScanTarget
from template_loader import ScanTemplate, load_templates
from validator       import validate_url, ValidationError

logger = logging.getLogger("ScanEngine")


# ──────────────────────────────────────────────
# 단일 요청 실행 (비동기)
# ──────────────────────────────────────────────

async def _execute_async(
    client:  httpx.AsyncClient,
    method:  str,
    url:     str,
    headers: dict,
    content: bytes | None,
    timeout: float,
) -> tuple[httpx.Response | None, float, str]:
    """비동기 HTTP 요청 실행. (response, elapsed, error) 반환."""
    try:
        t0   = time.perf_counter()
        resp = await client.request(
            method  = method,
            url     = url,
            headers = headers,
            content = content,
            timeout = timeout,
            follow_redirects = True,
        )
        return resp, time.perf_counter() - t0, ""
    except httpx.TimeoutException:
        return None, timeout, "Timeout"
    except httpx.RequestError as exc:
        return None, 0.0, f"요청 오류: {exc}"
    except Exception as exc:
        return None, 0.0, f"알 수 없는 오류: {exc}"


# ──────────────────────────────────────────────
# 단일 (target × template × payload) 실행
# ──────────────────────────────────────────────

async def _scan_one_async(
    target:    ScanTarget,
    template:  ScanTemplate,
    payload:   str,
    client:    httpx.AsyncClient,
    timeout:   float,
    semaphore: asyncio.Semaphore,
    delay:     float,
) -> ScanResult:
    """하나의 페이로드를 하나의 타겟에 삽입하고 결과 반환."""

    # 메서드 / 포지션 필터
    if target.method.upper() not in template.allowed_methods:
        return ScanResult(
            target=target, template_id=template.id,
            template_name=template.name, severity=template.severity,
            payload=payload, matched=False,
            error=f"건너뜀: 메서드 {target.method!r} 미허용",
        )
    if target.position not in template.allowed_positions:
        return ScanResult(
            target=target, template_id=template.id,
            template_name=template.name, severity=template.severity,
            payload=payload, matched=False,
            error=f"건너뜀: 위치 {target.position!r} 미허용",
        )

    # URL 유효성 검증
    try:
        validate_url(target.url)
    except ValidationError as exc:
        return ScanResult(
            target=target, template_id=template.id,
            template_name=template.name, severity=template.severity,
            payload=payload, matched=False, error=str(exc),
        )

    # PreparedRequest 빌드
    try:
        prepared = build_request(
            target          = target,
            payload         = payload,
            method_override = target.method,
            extra_headers   = template.headers,
        )
    except Exception as exc:
        return ScanResult(
            target=target, template_id=template.id,
            template_name=template.name, severity=template.severity,
            payload=payload, matched=False, error=str(exc),
        )

    # httpx용 파라미터 추출
    method  = prepared.method or "GET"
    url     = str(prepared.url) if prepared.url else target.url
    headers = dict(prepared.headers)
    content = prepared.body if isinstance(prepared.body, bytes) else (
        prepared.body.encode() if prepared.body else None
    )

    # rate limit 적용 후 요청
    async with semaphore:
        if delay > 0:
            await asyncio.sleep(delay)
        resp, elapsed, error = await _execute_async(
            client, method, url, headers, content, timeout
        )

    # requests.Response 호환 래퍼 → evaluate_matchers 재사용
    compat_resp = _HttpxResponseAdapter(resp) if resp is not None else None
    matched, match_results = evaluate_matchers(template, compat_resp, elapsed)

    return ScanResult(
        target        = target,
        template_id   = template.id,
        template_name = template.name,
        severity      = template.severity,
        payload       = payload,
        matched       = matched,
        match_results = match_results,
        elapsed       = round(elapsed, 3),
        status_code   = resp.status_code if resp else 0,
        response_body = resp.text[:2000] if resp else "",
        error         = error,
    )


class _HttpxResponseAdapter:
    """httpx.Response를 evaluate_matchers가 기대하는 인터페이스로 변환."""

    def __init__(self, resp: httpx.Response) -> None:
        self._resp = resp

    @property
    def text(self) -> str:
        return self._resp.text

    @property
    def content(self) -> bytes:
        return self._resp.content

    @property
    def status_code(self) -> int:
        return self._resp.status_code

    @property
    def headers(self):
        return self._resp.headers


# ──────────────────────────────────────────────
# 공개 엔진 클래스
# ──────────────────────────────────────────────

class ScanEngine:
    """
    비동기 페이로드 삽입 엔진.

    Parameters
    ----------
    templates_root   : 템플릿 루트 경로 (기본 "templates/")
    categories       : 로드할 카테고리 폴더명 리스트. None이면 전체.
    template_ids     : 특정 템플릿 ID만 로드. None이면 전체.
    request_timeout  : 기본 타임아웃 (초). time matcher가 있으면 자동 연장.
    max_concurrency  : 최대 동시 요청 수 (기본 10).
    requests_per_sec : 초당 요청 수 제한 (기본 5.0).
    """

    def __init__(
        self,
        templates_root:   str | Path        = "templates",
        categories:       list[str] | None  = None,
        template_ids:     list[str] | None  = None,
        request_timeout:  float             = 10.0,
        max_concurrency:  int               = 10,
        requests_per_sec: float             = 5.0,
    ) -> None:
        self.templates        = load_templates(templates_root, categories, template_ids)
        self.base_timeout     = request_timeout
        self.max_concurrency  = max_concurrency
        self.request_delay    = 1.0 / max(requests_per_sec, 0.1)

        if not self.templates:
            logger.warning("로드된 템플릿이 없습니다. 경로·카테고리를 확인하세요.")

    def _timeout_for(self, template: ScanTemplate) -> float:
        """time matcher가 있으면 delay + 3초를 타임아웃으로 사용."""
        for m in template.matchers:
            if m.type == "time":
                delay = float(m.data.get("delay", 5))
                return max(self.base_timeout, delay + 3)
        return self.base_timeout

    # ── 비동기 실행 메서드 ────────────────────────

    async def run_async(
        self,
        targets:           list[ScanTarget],
        stop_on_first_hit: bool = False,
    ) -> list[ScanResult]:
        """비동기 스캔 실행. List[ScanResult] 반환."""
        semaphore = asyncio.Semaphore(self.max_concurrency)
        all_results: list[ScanResult] = []

        async with httpx.AsyncClient(
            verify         = False,   # 자체 서명 인증서 허용
            follow_redirects = True,
            limits         = httpx.Limits(max_connections=self.max_concurrency + 5),
        ) as client:
            tasks = []

            for target in targets:
                for template in self.templates:
                    timeout = self._timeout_for(template)
                    for payload in template.payloads:
                        tasks.append(
                            _scan_one_async(
                                target, template, payload,
                                client, timeout, semaphore,
                                self.request_delay,
                            )
                        )

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                logger.error("스캔 태스크 예외: %s", r)
                continue
            all_results.append(r)
            self._log(r)

        return all_results

    # ── 동기 래퍼 (CLI에서 직접 호출 가능) ───────

    def run(
        self,
        targets:           list[ScanTarget],
        stop_on_first_hit: bool = False,
    ) -> list[ScanResult]:
        """동기 래퍼. 내부적으로 asyncio 이벤트 루프를 생성·실행."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 이미 이벤트 루프가 실행 중인 경우 (Jupyter 등)
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    future = pool.submit(
                        lambda: asyncio.run(self.run_async(targets, stop_on_first_hit))
                    )
                    return future.result()
        except RuntimeError:
            pass
        return asyncio.run(self.run_async(targets, stop_on_first_hit))

    # ── 로그 출력 ─────────────────────────────────

    @staticmethod
    def _log(r: ScanResult) -> None:
        if r.error and not r.matched:
            tag = "[SKIP ]"
        elif r.matched:
            tag = "[VULN!]"
        else:
            tag = "[ OK  ]"

        line = (
            f"{tag} [{r.template_id}] {r.target.url} "
            f"| param={r.target.param!r} | payload={r.payload!r} "
            f"| {r.elapsed}s | HTTP {r.status_code}"
        )
        if r.error:
            line += f" | 오류={r.error}"
        if r.matched:
            hits = [f"{mr.mtype}:{mr.detail}" for mr in r.match_results if mr.hit]
            line += f" | 매치={hits}"

        if r.matched:
            logger.warning(line)
        elif r.error and not r.matched:
            logger.debug(line)
        else:
            logger.debug(line)
