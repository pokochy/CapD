"""
core/reporter.py — 스캔 결과 출력 및 저장

지원 형식:
  - 콘솔 요약 출력
  - JSON 파일 저장
  - 텍스트 리포트 저장
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from models import ScanResult

logger = logging.getLogger("Reporter")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_results(results: list[ScanResult]) -> list[ScanResult]:
    return sorted(
        results,
        key=lambda r: _SEVERITY_ORDER.get(r.severity, 99),
    )


def print_summary(results: list[ScanResult]) -> None:
    """콘솔에 스캔 요약 출력."""
    vulns  = [r for r in results if r.matched]
    errors = [r for r in results if r.error and not r.matched]

    print("\n" + "=" * 65)
    print("  스캔 결과 요약")
    print("=" * 65)
    print(f"  전체 검사 수  : {len(results)}")
    print(f"  취약점 발견   : {len(vulns)}")
    print(f"  오류/건너뜀   : {len(errors)}")
    print("=" * 65)

    if not vulns:
        print("  취약점이 발견되지 않았습니다.\n")
        return

    print("\n  [발견된 취약점]\n")
    for v in _sort_results(vulns):
        hits = [mr.mtype for mr in v.match_results if mr.hit]
        print(
            f"  [{v.severity.upper():8}] {v.template_id}\n"
            f"    URL     : {v.target.url}\n"
            f"    파라미터 : {v.target.param}\n"
            f"    페이로드 : {v.payload!r}\n"
            f"    매치     : {hits}\n"
            f"    응답시간 : {v.elapsed}s | HTTP {v.status_code}\n"
        )
    print("=" * 65 + "\n")


def save_json(results: list[ScanResult], output_path: str | Path) -> None:
    """결과를 JSON 파일로 저장."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "scan_time":    datetime.now().isoformat(),
        "total":        len(results),
        "vulnerabilities": len([r for r in results if r.matched]),
        "results":      [_result_to_dict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    logger.info("JSON 리포트 저장: %s", path)


def save_text(results: list[ScanResult], output_path: str | Path) -> None:
    """결과를 텍스트 파일로 저장."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    vulns = [r for r in results if r.matched]
    lines = [
        "=" * 65,
        f"  웹 취약점 스캔 리포트",
        f"  생성 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 65,
        f"  전체 검사 수 : {len(results)}",
        f"  취약점 발견  : {len(vulns)}",
        "=" * 65,
        "",
    ]

    for v in _sort_results(vulns):
        hits = [mr.mtype for mr in v.match_results if mr.hit]
        lines += [
            f"[{v.severity.upper()}] {v.template_id} — {v.template_name}",
            f"  URL      : {v.target.url}",
            f"  파라미터  : {v.target.param}",
            f"  위치      : {v.target.position}",
            f"  페이로드  : {v.payload}",
            f"  매치 유형 : {hits}",
            f"  응답 코드 : {v.status_code}",
            f"  응답 시간 : {v.elapsed}s",
            "",
        ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info("텍스트 리포트 저장: %s", path)


def _result_to_dict(r: ScanResult) -> dict:
    """ScanResult를 JSON 직렬화 가능한 dict로 변환."""
    return {
        "matched":       r.matched,
        "template_id":   r.template_id,
        "template_name": r.template_name,
        "severity":      r.severity,
        "url":           r.target.url,
        "param":         r.target.param,
        "position":      r.target.position,
        "method":        r.target.method,
        "payload":       r.payload,
        "status_code":   r.status_code,
        "elapsed":       r.elapsed,
        "error":         r.error,
        "match_results": [
            {"type": mr.mtype, "hit": mr.hit, "detail": mr.detail}
            for mr in r.match_results
        ],
    }
