"""
crawler.py — 비동기 웹 크롤러
aiohttp 기반으로 링크 / 폼 / 쿼리 파라미터를 수집한다.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp
from bs4 import BeautifulSoup

from models import FormField, CrawledForm, CrawledPage


# ── 링크 추출기 ─────────────────────────────────────────

class LinkExtractor:
    LINK_ATTRS = {
        "a": "href", "link": "href", "script": "src",
        "img": "src", "iframe": "src", "form": "action",
    }

    def extract(self, html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []
        for tag, attr in self.LINK_ATTRS.items():
            for el in soup.find_all(tag):
                href = el.get(attr)
                if not href:
                    continue
                absolute = urljoin(base_url, href.strip())
                if absolute.startswith(("http://", "https://")):
                    links.append(absolute)
        return list(set(links))


# ── 폼 추출기 ───────────────────────────────────────────

class FormExtractor:
    INJECTABLE_TYPES = {
        "text", "password", "email", "search", "url",
        "number", "tel", "hidden", "textarea",
    }

    def extract(self, html: str, base_url: str) -> list[CrawledForm]:
        soup  = BeautifulSoup(html, "html.parser")
        forms: list[CrawledForm] = []
        for form_tag in soup.find_all("form"):
            action   = form_tag.get("action", "")
            abs_action = urljoin(base_url, action) if action else base_url
            method   = (form_tag.get("method") or "get").upper()
            fields   = self._extract_fields(form_tag)
            forms.append(CrawledForm(
                action=abs_action, method=method,
                fields=fields, found_on=base_url,
            ))
        return forms

    def _extract_fields(self, form_tag) -> list[FormField]:
        fields: list[FormField] = []
        for inp in form_tag.find_all("input"):
            name = inp.get("name", "")
            if not name:
                continue
            fields.append(FormField(
                name=name,
                field_type=(inp.get("type") or "text").lower(),
                value=inp.get("value", ""),
            ))
        for ta in form_tag.find_all("textarea"):
            name = ta.get("name", "")
            if name:
                fields.append(FormField(name=name, field_type="textarea", value=ta.get_text()))
        for sel in form_tag.find_all("select"):
            name = sel.get("name", "")
            if name:
                opts = [o.get("value", o.get_text()) for o in sel.find_all("option")]
                fields.append(FormField(name=name, field_type="select", options=opts))
        return fields


# ── URL 큐 ──────────────────────────────────────────────

class URLQueue:
    """BFS 기반 URL 큐 — 중복 제거 / 도메인 필터 / 깊이 제한"""

    def __init__(self, base_url: str, max_depth: int = 3):
        self.target_domain = urlparse(base_url).netloc
        self.max_depth     = max_depth
        self._queue: deque[tuple[str, int]] = deque()
        self._visited: set[str] = set()

    def push(self, url: str, depth: int) -> None:
        normalized = url.split("#")[0].rstrip("/")
        if (normalized in self._visited
                or urlparse(normalized).netloc != self.target_domain
                or depth > self.max_depth):
            return
        self._visited.add(normalized)
        self._queue.append((normalized, depth))

    def pop(self) -> Optional[tuple[str, int]]:
        return self._queue.popleft() if self._queue else None

    def is_empty(self) -> bool:
        return not self._queue

    def visited_count(self) -> int:
        return len(self._visited)


# ── 웹 크롤러 ───────────────────────────────────────────

class WebCrawler:
    """비동기 BFS 웹 크롤러"""

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/2.0)",
        "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(
        self,
        start_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        concurrency: int = 5,
        request_delay: float = 0.5,
        timeout: int = 10,
    ):
        self.start_url     = start_url
        self.max_pages     = max_pages
        self.concurrency   = concurrency
        self.request_delay = request_delay
        self.timeout       = aiohttp.ClientTimeout(total=timeout)
        self.queue         = URLQueue(start_url, max_depth=max_depth)
        self.link_ex       = LinkExtractor()
        self.form_ex       = FormExtractor()
        self.results: list[CrawledPage] = []
        self._sem: asyncio.Semaphore | None = None
        self.logger        = logging.getLogger("WebCrawler")

    async def crawl(self) -> list[CrawledPage]:
        self._sem = asyncio.Semaphore(self.concurrency)
        self.queue.push(self.start_url, depth=0)

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            headers=self.DEFAULT_HEADERS,
            connector=connector,
            timeout=self.timeout,
        ) as session:
            tasks: list = []
            while not self.queue.is_empty() and len(self.results) < self.max_pages:
                url, depth = self.queue.pop()
                tasks.append(self._crawl_page(session, url, depth))
                if len(tasks) >= self.concurrency or self.queue.is_empty():
                    await asyncio.gather(*tasks, return_exceptions=True)
                    tasks = []
                    await asyncio.sleep(self.request_delay)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.info(
            "크롤링 완료 — 페이지 %d개 / 방문 URL %d개",
            len(self.results), self.queue.visited_count(),
        )
        return self.results

    async def _crawl_page(
        self, session: aiohttp.ClientSession, url: str, depth: int
    ) -> None:
        async with self._sem:
            try:
                self.logger.info("[depth=%d] %s", depth, url)
                async with session.get(url, allow_redirects=True) as resp:
                    await self._process_response(resp, url, depth)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                self.logger.warning("실패 (%s): %s", url, e)

    async def _process_response(
        self, response: aiohttp.ClientResponse, url: str, depth: int
    ) -> None:
        content_type = response.headers.get("Content-Type", "")
        links, forms = [], []

        if "text/html" in content_type:
            html  = await response.text(errors="replace")
            links = self.link_ex.extract(html, url)
            forms = self.form_ex.extract(html, url)
            for link in links:
                self.queue.push(link, depth + 1)

        query_params = {
            k: (v[0] if v else "")
            for k, v in parse_qs(urlparse(url).query).items()
        }

        self.results.append(CrawledPage(
            url=url, status_code=response.status, content_type=content_type,
            links=links, forms=forms, query_params=query_params,
            response_headers=dict(response.headers), depth=depth,
        ))

        if forms:
            self.logger.info("  └─ 폼 %d개 (action=%s)", len(forms), forms[0].action)
        if query_params:
            self.logger.info("  └─ 쿼리 파라미터: %s", list(query_params.keys()))
