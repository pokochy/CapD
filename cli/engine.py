"""
engine.py — 통합 취약점 스캔 엔진

piece 2 ScanEngine + piece 6 InjectionScanner 를 통합.

핵심 개선사항:
  - 모든 주입 위치 지원: query / body / cookie / header / form_field / path
  - 모든 matcher 타입 지원: word / status / time
  - definition.method / definition.position 필터링 유지
  - 멀티스레드 병렬 실행
  - YAML 포맷 통일 (아래 참조)

지원 YAML 포맷:
  definition:
    method:   [GET, POST, ...]   # 허용 메소드 필터
    position: [query, body, ...]  # 허용 위치 필터
  payloads: [...]
  matchers-condition: or | and
  matchers:
    - type: word
      words: [keyword1, keyword2]
    - type: status
      status: [500, 503]
    - type: time
      delay: 5
"""
from __future__ import annotations

import concurrent.futures
import logging
import os
from typing import Optional
from urllib.parse import urljoin, quote

import requests
import yaml

from models import ScanTarget, Finding

logger = logging.getLogger("ScanEngine")


class ScanEngine:
    """YAML 템플릿 기반 멀티스레드 취약점 스캔 엔진"""

    def __init__(self, template_dir: str = "templates", max_workers: int = 5):
        self.template_dir = template_dir
        self.max_workers  = max_workers
        self.session      = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/2.0)",
        })
        self.templates = self.load_templates()
        self.findings: list[Finding] = []

    # ── 템플릿 로드 ──────────────────────────────────────

    def load_templates(self) -> list[dict]:
        templates: list[dict] = []
        if not os.path.exists(self.template_dir):
            logger.warning("'%s' 폴더가 없습니다.", self.template_dir)
            return templates

        for root, _, files in os.walk(self.template_dir):
            for fname in files:
                if not (fname.endswith(".yaml") or fname.endswith(".yml")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, encoding="utf-8") as f:
                        tpl = yaml.safe_load(f)
                        if tpl:
                            templates.append(tpl)
                            logger.debug("템플릿 로드: %s", fname)
                except Exception as e:
                    logger.warning("%s 로드 실패: %s", fname, e)

        logger.info("템플릿 %d개 로드 완료", len(templates))
        return templates

    # ── 스캔 실행 ────────────────────────────────────────

    def run_scan(self, targets: list[ScanTarget]) -> list[Finding]:
        """ScanTarget 목록 × 전체 템플릿 스캔. Finding 목록 반환."""
        self.findings = []
        total = len(targets) * len(self.templates)
        logger.info(
            "스캔 시작 — 타겟 %d × 템플릿 %d = 최대 %d회 검사",
            len(targets), len(self.templates), total,
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as exe:
            futures = [
                exe.submit(self._check, target, tpl)
                for target in targets
                for tpl in self.templates
            ]
            concurrent.futures.wait(futures)

        logger.info("스캔 완료 — 취약점 %d건 발견", len(self.findings))
        return self.findings

    # ── 단일 (타겟, 템플릿) 검사 ─────────────────────────

    def _check(self, target: ScanTarget, template: dict) -> None:
        info      = template.get("info", {})
        vuln_name = info.get("name", "Unknown")
        severity  = info.get("severity", "medium")
        defn      = template.get("definition", {})
        payloads  = template.get("payloads", [])
        matchers  = template.get("matchers", [])
        condition = template.get("matchers-condition", "or").lower()

        # definition 필터: 허용 메소드 / 위치가 아니면 스킵
        allowed_methods   = [m.upper() for m in defn.get("method",   [])]
        allowed_positions = defn.get("position", [])

        if allowed_methods and target.method.upper() not in allowed_methods:
            return
        if allowed_positions and target.position not in allowed_positions:
            return

        for payload in payloads:
            try:
                resp = self._send_attack(target, payload)
                evidence = self.verify(resp, matchers, condition)
                if evidence:
                    finding = Finding(
                        vulnerability=vuln_name,
                        severity=severity,
                        position=target.position,
                        url=target.url,
                        method=target.method,
                        inject_param=target.name,
                        payload=payload,
                        evidence=evidence,
                        found_on=target.found_on,
                    )
                    self.findings.append(finding)
                    logger.warning(
                        "🚨 [%s] %s — %s %s (param=%s, evidence=%s)",
                        severity.upper(), vuln_name,
                        target.method, target.url, target.name, evidence,
                    )
                    return   # 같은 템플릿에서 첫 히트 후 중단 (최적화)

            except requests.exceptions.RequestException:
                pass

    # ── 위치별 공격 전송 ─────────────────────────────────

    def _send_attack(self, target: ScanTarget, payload: str) -> requests.Response:
        pos    = target.position
        url    = target.url
        name   = target.name
        method = target.method.upper()

        # query / form_field(GET) — URL 파라미터 주입
        if pos in ("query",) or (pos == "form_field" and method == "GET"):
            data = dict(target.base_data)
            data[name] = payload
            return self.session.get(url, params=data, timeout=10)

        # body / form_field(POST) — POST 데이터 주입
        if pos in ("body",) or (pos == "form_field" and method == "POST"):
            data = dict(target.base_data)
            data[name] = payload
            return self.session.post(url, data=data, timeout=10)

        # cookie — Cookie 헤더 주입
        if pos == "cookie":
            return self.session.request(
                method=method, url=url,
                cookies={name: payload}, timeout=10,
            )

        # header — 커스텀 헤더 주입
        if pos == "header":
            return self.session.request(
                method=method, url=url,
                headers={name: payload}, timeout=10,
            )

        # path (레거시) — URL 경로 내 {{PAYLOAD}} 치환
        if pos == "path":
            encoded = quote(payload)
            full_url = url.replace("{{PAYLOAD}}", encoded)
            return self.session.request(method=method, url=full_url, timeout=10)

        raise ValueError(f"지원하지 않는 position: {pos}")

    # ── 매처 검증 ────────────────────────────────────────

    def verify(
        self,
        response: requests.Response,
        matchers: list[dict],
        condition: str = "or",
    ) -> Optional[str]:
        """
        matchers 를 평가하고 매치된 증거 문자열을 반환.
        매치 실패 시 None 반환.

        condition = "or"  → 하나라도 매치되면 통과
        condition = "and" → 모두 매치되어야 통과
        """
        results: list[Optional[str]] = []

        for m in matchers:
            m_type = m.get("type")

            if m_type == "word":
                body_lower = response.text.lower()
                matched = next(
                    (w for w in m.get("words", []) if w.lower() in body_lower),
                    None,
                )
                results.append(matched)

            elif m_type == "status":
                if response.status_code in m.get("status", []):
                    results.append(f"status-{response.status_code}")
                else:
                    results.append(None)

            elif m_type == "time":
                delay = m.get("delay", 5)
                if response.elapsed.total_seconds() >= delay:
                    results.append(f"time-delay≥{delay}s")
                else:
                    results.append(None)

        if not results:
            return None

        if condition == "and":
            return None if any(r is None for r in results) else results[0]
        else:  # "or"
            return next((r for r in results if r is not None), None)
