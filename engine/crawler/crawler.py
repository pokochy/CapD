"""
engine/crawler/crawler.py
──────────────────────────
2단계: 대상 URL을 크롤링하여 입력 포인트(query params, form fields)를 수집.
Headless 브라우저 없이 정적 HTML 파싱으로 구현 (경량 버전).
"""

from __future__ import annotations

import os
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from utils.http_client import HttpClient
from utils.logger import get_logger

logger = get_logger("crawler")

_MAX_DEPTH = int(os.getenv("SCAN_MAX_DEPTH", "3"))
_MAX_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "5"))


class Crawler:
    """
    BFS 방식으로 대상 도메인 내 URL을 탐색.
    발견된 입력 포인트(쿼리스트링, 폼 필드)를 반환.
    """

    def __init__(self) -> None:
        self.visited: set[str] = set()
        self.input_points: list[dict] = []

    async def run(self, start_url: str) -> list[dict]:
        """
        크롤링 실행.
        반환: [{"url": str, "method": str, "position": str, "params": [str]}, ...]
        """
        logger.info(f"[Crawler] Starting crawl: {start_url}")
        base_domain = urlparse(start_url).netloc

        queue = [(start_url, 0)]

        async with HttpClient() as client:
            while queue:
                url, depth = queue.pop(0)
                if url in self.visited or depth > _MAX_DEPTH:
                    continue

                self.visited.add(url)
                resp = await client.get(url)
                if resp.get("status", 0) == 0:
                    continue

                body = resp.get("body", "")
                self._extract_query_inputs(url)
                new_links, form_inputs = self._parse_html(url, body, base_domain)
                self.input_points.extend(form_inputs)

                for link in new_links:
                    if link not in self.visited:
                        queue.append((link, depth + 1))

        # 쿼리스트링이 있는 visited URL도 입력 포인트로 추가
        logger.info(f"[Crawler] Found {len(self.input_points)} input points from {len(self.visited)} pages")
        return self.input_points

    def _extract_query_inputs(self, url: str) -> None:
        """URL의 쿼리스트링 파라미터를 입력 포인트로 등록."""
        parsed = urlparse(url)
        if parsed.query:
            params = list(parse_qs(parsed.query).keys())
            if params:
                self.input_points.append({
                    "url": url,
                    "method": "GET",
                    "position": "query",
                    "params": params,
                })

    def _parse_html(
        self, base_url: str, html: str, base_domain: str
    ) -> tuple[list[str], list[dict]]:
        """HTML에서 링크와 폼 입력 포인트를 추출."""
        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []
        form_inputs: list[dict] = []

        # <a href> 링크 수집 (같은 도메인만)
        for tag in soup.find_all("a", href=True):
            href = urljoin(base_url, tag["href"])
            if urlparse(href).netloc == base_domain:
                links.append(href.split("#")[0])  # fragment 제거

        # <form> 폼 수집
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", base_url))
            method = (form.get("method", "GET")).upper()
            fields = [
                inp.get("name")
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]
            if fields:
                form_inputs.append({
                    "url": action,
                    "method": method,
                    "position": "form_field",
                    "params": fields,
                })

        return links, form_inputs
