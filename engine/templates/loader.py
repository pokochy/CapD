"""
engine/templates/loader.py
──────────────────────────
YAML 취약점 템플릿을 동적으로 로드하고 파싱하는 모듈.
/templates 디렉터리의 모든 .yaml 파일을 자동 탐색하므로
템플릿 추가/제거 시 코드 수정 없이 반영됩니다.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

TEMPLATES_DIR = Path(__file__).parent


class TemplateLoader:
    """YAML 탐지 템플릿을 로드·파싱·캐싱하는 싱글톤 로더."""

    def __init__(self) -> None:
        self._cache: dict[str, dict] = {}

    # ── Public API ──────────────────────────────────────────────────────────

    def load_all(self) -> list[dict]:
        """템플릿 디렉터리의 모든 .yaml 파일을 로드하여 반환."""
        templates: list[dict] = []
        for yaml_path in sorted(TEMPLATES_DIR.glob("*.yaml")):
            tmpl = self._load_file(yaml_path)
            if tmpl:
                templates.append(tmpl)
        return templates

    def load_by_id(self, template_id: str) -> dict | None:
        """특정 ID의 템플릿만 로드."""
        for yaml_path in TEMPLATES_DIR.glob("*.yaml"):
            tmpl = self._load_file(yaml_path)
            if tmpl and tmpl.get("id") == template_id:
                return tmpl
        return None

    def list_ids(self) -> list[str]:
        """사용 가능한 모든 템플릿 ID 목록 반환."""
        ids: list[str] = []
        for yaml_path in TEMPLATES_DIR.glob("*.yaml"):
            tmpl = self._load_file(yaml_path)
            if tmpl and "id" in tmpl:
                ids.append(tmpl["id"])
        return ids

    def get_all_payloads(self, template: dict) -> list[dict]:
        """
        템플릿에서 payload_groups를 읽어 평탄화된 페이로드 리스트 반환.
        반환 형식: [{"payload": str, "group": str, "engine": str}, ...]
        """
        result: list[dict] = []
        for group in template.get("payload_groups", []):
            for payload in group.get("payloads", []):
                result.append(
                    {
                        "payload": payload,
                        "group": group.get("group", "unknown"),
                        "engine": group.get("engine", "unknown"),
                    }
                )
        return result

    def compile_matchers(self, template: dict) -> list[dict]:
        """
        matchers 목록에서 정규식을 미리 컴파일하여 반환.
        반환 형식: [{"name": str, "patterns": [compiled_re], "type": str}, ...]
        """
        compiled: list[dict] = []
        for matcher in template.get("matchers", []):
            if matcher.get("type") == "regex":
                patterns = [
                    re.compile(p, re.IGNORECASE)
                    for p in matcher.get("regex", [])
                ]
                compiled.append(
                    {
                        "name": matcher.get("name", "unnamed"),
                        "description": matcher.get("description", ""),
                        "type": "regex",
                        "patterns": patterns,
                    }
                )
        return compiled

    # ── Internal ─────────────────────────────────────────────────────────────

    def _load_file(self, path: Path) -> dict | None:
        """단일 YAML 파일 로드 (캐시 우선)."""
        key = str(path)
        if key not in self._cache:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._cache[key] = yaml.safe_load(f) or {}
            except Exception as exc:
                print(f"[TemplateLoader] Failed to load {path}: {exc}")
                return None
        return self._cache[key]


# 싱글톤 인스턴스
template_loader = TemplateLoader()
