from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

from models import Method, Position

logger = logging.getLogger("TemplateLoader")


@dataclass
class MatcherDef:
    type: str
    data: dict
    condition: Literal["or", "and"] = "or"
    negate: bool = False


@dataclass
class ScanTemplate:
    id: str
    name: str
    severity: str
    description: str
    category: str
    source_path: Path
    allowed_methods: list[Method]
    allowed_positions: list[Position]
    payloads: list[str]
    matchers: list[MatcherDef]
    matchers_condition: Literal["or", "and"]
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    max_redirects: int = 5


def _parse_matcher(raw: dict) -> MatcherDef:
    return MatcherDef(
        type=raw["type"],
        data={k: v for k, v in raw.items() if k not in ("type", "condition", "negate")},
        condition=raw.get("condition", "or"),
        negate=raw.get("negate", False),
    )


def _parse_template(path: Path, category: str) -> ScanTemplate:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"올바르지 않은 템플릿 형식: {path}")
    if not raw.get("id"):
        raise ValueError(f"템플릿 id 누락: {path}")
    if not raw.get("payloads"):
        raise ValueError(f"payloads 누락: {path}")

    info = raw.get("info", {})
    defn = raw.get("definition", {})

    return ScanTemplate(
        id=raw["id"],
        name=info.get("name", path.stem),
        severity=info.get("severity", "info").lower(),
        description=info.get("description", ""),
        category=category,
        source_path=path,
        allowed_methods=[m.upper() for m in defn.get("method", ["GET", "POST"])],
        allowed_positions=defn.get("position", ["query", "body"]),
        payloads=[str(p) for p in raw.get("payloads", [])],
        matchers=[_parse_matcher(m) for m in raw.get("matchers", [])],
        matchers_condition=raw.get("matchers-condition", "or").lower(),
        headers=raw.get("headers", {}),
        follow_redirects=raw.get("follow-redirects", True),
        max_redirects=raw.get("max-redirects", 5),
    )


def _iter_template_files(root: Path) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []

    for yaml_file in sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml")):
        category = root.name if root.name not in ("", ".") else "default"
        files.append((yaml_file, category))

    for category_dir in sorted(root.iterdir()):
        if not category_dir.is_dir():
            continue
        for yaml_file in sorted(category_dir.glob("**/*.yaml")) + sorted(category_dir.glob("**/*.yml")):
            files.append((yaml_file, category_dir.name))

    return files


def load_templates(
    templates_root: str | Path = "templates",
    categories: list[str] | None = None,
    template_ids: list[str] | None = None,
) -> list[ScanTemplate]:
    root = Path(templates_root)
    result: list[ScanTemplate] = []

    if not root.exists():
        raise FileNotFoundError(f"템플릿 디렉터리를 찾을 수 없습니다: {root}")

    for yaml_file, category in _iter_template_files(root):
        if categories and category not in categories:
            continue

        try:
            tmpl = _parse_template(yaml_file, category)
            if template_ids and tmpl.id not in template_ids:
                continue
            result.append(tmpl)
            logger.debug("템플릿 로드: %s (%s)", tmpl.id, yaml_file)
        except Exception as exc:
            logger.warning("템플릿 로드 실패 [%s]: %s", yaml_file, exc)

    logger.info(
        "템플릿 %d개 로드 완료 (루트: %s, 카테고리: %s, ID 필터: %s)",
        len(result),
        root,
        categories or "전체",
        template_ids or "전체",
    )
    return result
