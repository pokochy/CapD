"""
pipeline.py — 전체 스캔 파이프라인 오케스트레이터
"""
from __future__ import annotations

import asyncio
import logging
import os

import yaml

from fingerprinter import fingerprint, print_fingerprint
from crawler import WebCrawler
from analyzer import Analyzer
from engine import ScanEngine
from reporter import ReportGenerator, make_report_dir
from models import Finding, CrawledPage


def _create_default_templates(template_dir: str = "templates") -> None:
    os.makedirs(template_dir, exist_ok=True)
    defaults = {
        "sqli.yaml": {
            "id": "sqli-error-time",
            "info": {"name": "SQL Injection", "severity": "critical",
                     "description": "에러 기반 및 시간 지연 기반 통합 SQLi 스캔"},
            "definition": {"method": ["GET","POST","PUT"],
                           "position": ["query","body","cookie","header","form_field"]},
            "payloads": ["' OR 1=1--","' OR '1'='1","1; DROP TABLE users--",
                         "' AND SLEEP(5)--","'; WAITFOR DELAY '0:0:5'--"],
            "matchers-condition": "or",
            "matchers": [
                {"type":"word","words":["sql syntax","mysql_fetch","ora-","pg_query",
                                        "sqlite","syntax error","unclosed quotation",
                                        "you have an error in your sql"]},
                {"type":"status","status":[500,503]},
                {"type":"time","delay":5},
            ],
        },
        "xss.yaml": {
            "id": "xss-reflected",
            "info": {"name": "Reflected XSS", "severity": "high", "description": "반사형 XSS 스캔"},
            "definition": {"method": ["GET","POST"],
                           "position": ["query","body","form_field"]},
            "payloads": ["<script>alert(1)</script>","<img src=x onerror=alert(1)>",
                         '"><script>alert(document.domain)</script>',"javascript:alert(1)"],
            "matchers-condition": "or",
            "matchers": [{"type":"word","words":["<script>alert","onerror=alert","javascript:alert"]}],
        },
        "path_traversal.yaml": {
            "id": "path-traversal",
            "info": {"name": "Path Traversal", "severity": "high", "description": "경로 탐색 취약점 스캔"},
            "definition": {"method": ["GET"], "position": ["query","form_field"]},
            "payloads": ["../../../../etc/passwd","..%2F..%2F..%2Fetc%2Fpasswd",
                         "....//....//....//etc/passwd"],
            "matchers-condition": "or",
            "matchers": [{"type":"word","words":["root:x:","root:0:0:","/bin/bash","nobody:x:"]}],
        },
    }
    for fname, content in defaults.items():
        fpath = os.path.join(template_dir, fname)
        if not os.path.exists(fpath):
            with open(fpath, "w", encoding="utf-8") as f:
                yaml.dump(content, f, allow_unicode=True, default_flow_style=False)
            print(f"  [+] 기본 템플릿 생성: {fname}")


class VulnScanPipeline:

    def __init__(
        self,
        target_url: str,
        template_dir: str = "templates",
        max_depth: int = 2,
        max_pages: int = 50,
        crawl_concurrency: int = 3,
        scan_workers: int = 5,
        request_delay: float = 0.3,
        output_json: str = "scan_report.json",
        skip_fingerprint: bool = False,
    ):
        self.target_url       = target_url
        self.output_json      = output_json
        self.skip_fingerprint = skip_fingerprint
        self.crawler  = WebCrawler(start_url=target_url, max_depth=max_depth,
                                   max_pages=max_pages, concurrency=crawl_concurrency,
                                   request_delay=request_delay)
        self.analyzer = Analyzer()
        self.engine   = ScanEngine(template_dir=template_dir, max_workers=scan_workers)
        self.reporter = ReportGenerator()

    def run(self) -> list[Finding]:
        fp_result  = None
        report_dir = make_report_dir("reports")
        json_path  = os.path.join(report_dir, "scan_report.json")
        html_path  = os.path.join(report_dir, "scan_report.html")

        # Phase 0: 핑거프린팅
        if not self.skip_fingerprint:
            print("\n" + "─" * 68)
            print("  [Phase 0] 핑거프린팅 — 기술 스택 파악")
            print("─" * 68)
            fp_result = fingerprint(self.target_url)
            print_fingerprint(fp_result)

        # Phase 1: 크롤링
        print("\n" + "─" * 68)
        print("  [Phase 1] 크롤링 — 공격 표면 수집")
        print("─" * 68)
        pages: list[CrawledPage] = asyncio.run(self.crawler.crawl())

        # Phase 2: 타겟 분석
        print("\n" + "─" * 68)
        print("  [Phase 2] 크롤링 결과 → 주입 타겟 분석")
        print("─" * 68)
        targets = self.analyzer.build_targets(pages)

        if not targets:
            print("  주입 가능한 대상이 없습니다. 스캔을 건너뜁니다.")
            self.reporter.print_report([], pages, fp_result)
            self.reporter.save_json([], fp_result, pages, json_path)
            self.reporter.generate_html([], fp_result, pages, html_path)
            print(f"\n  📁 결과 폴더: {report_dir}")
            return []

        # Phase 3: 인젝션 스캔
        print("\n" + "─" * 68)
        print("  [Phase 3] 템플릿 기반 인젝션 스캔")
        print("─" * 68)
        findings = self.engine.run_scan(targets)

        # Phase 4: 보고서
        print("\n" + "─" * 68)
        print("  [Phase 4] 보고서 생성")
        print("─" * 68)
        self.reporter.print_report(findings, pages, fp_result)
        self.reporter.save_json(findings, fp_result, pages, json_path)
        self.reporter.generate_html(findings, fp_result, pages, html_path)
        print(f"\n  📁 결과 폴더: {report_dir}")

        return findings
