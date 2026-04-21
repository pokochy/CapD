from __future__ import annotations

import logging
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from models import CrawledPage, FieldDef, FormDef

logger = logging.getLogger("Crawler")

_ALLOWED_FIELD_TYPES = {"text", "password", "email", "search", "url", "number", "tel", "hidden", "textarea"}


class _FormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[FormDef] = []
        self._current_form: FormDef | None = None
        self._current_textarea: FieldDef | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attr = {k.lower(): v for k, v in attrs}

        if tag == "form":
            action = urljoin(self.base_url, attr.get("action") or self.base_url)
            method = (attr.get("method") or "GET").upper()
            if method not in {"GET", "POST", "PUT", "PATCH"}:
                method = "GET"
            self._current_form = FormDef(action=action, method=method, fields=[], found_on=self.base_url)
            self.forms.append(self._current_form)
            return

        if self._current_form is None:
            return

        if tag == "input":
            name = (attr.get("name") or "").strip()
            if not name:
                return
            field_type = (attr.get("type") or "text").lower()
            value = attr.get("value") or ""
            self._current_form.fields.append(FieldDef(name=name, field_type=field_type, value=value))
            return

        if tag == "textarea":
            name = (attr.get("name") or "").strip()
            if not name:
                return
            self._current_textarea = FieldDef(name=name, field_type="textarea", value="")
            self._current_form.fields.append(self._current_textarea)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        elif tag == "textarea":
            self._current_textarea = None

    def handle_data(self, data: str) -> None:
        if self._current_textarea is not None:
            self._current_textarea.value += data


def discover_page(url: str, headers: dict[str, str] | None = None, timeout: float = 10.0) -> list[CrawledPage]:
    req_headers = {"User-Agent": "cap-scanner/1.0"}
    if headers:
        req_headers.update(headers)

    try:
        with httpx.Client(follow_redirects=True, verify=False, timeout=timeout, headers=req_headers) as client:
            resp = client.get(url)
    except Exception as exc:
        logger.warning("페이지 자동 분석 실패: %s", exc)
        return []

    final_url = str(resp.url)
    query_params = {k: v[0] for k, v in parse_qs(urlparse(final_url).query).items()}

    parser = _FormParser(final_url)
    content_type = resp.headers.get("Content-Type", "").lower()
    if "html" in content_type or "<form" in resp.text.lower():
        parser.feed(resp.text)

    forms = []
    for form in parser.forms:
        fields = [field for field in form.fields if field.field_type in _ALLOWED_FIELD_TYPES]
        forms.append(FormDef(action=form.action, method=form.method, fields=fields, found_on=form.found_on))

    page = CrawledPage(
        url=final_url,
        query_params=query_params,
        forms=forms,
        headers=dict(resp.headers),
        cookies={cookie.name: cookie.value for cookie in resp.cookies.jar},
    )

    logger.info("자동 분석 완료: %s (query: %d, forms: %d)", final_url, len(query_params), len(forms))
    return [page]
