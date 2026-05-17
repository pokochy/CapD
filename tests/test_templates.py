"""
tests/test_templates.py
────────────────────────
템플릿 로더 유닛 테스트 (unittest 표준 라이브러리 사용).

실행:
  python -m pytest tests/test_templates.py -v
  또는
  python tests/test_templates.py
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from engine.templates.loader import template_loader


class TestTemplateLoader(unittest.TestCase):

    def test_load_all_returns_list(self):
        """load_all()이 리스트를 반환해야 함."""
        templates = template_loader.load_all()
        self.assertIsInstance(templates, list)
        self.assertGreater(len(templates), 0, "최소 1개 이상의 템플릿이 있어야 함")

    def test_each_template_has_required_fields(self):
        """모든 템플릿에 id, info, payload_groups, matchers가 있어야 함."""
        for tmpl in template_loader.load_all():
            with self.subTest(template=tmpl.get("id")):
                self.assertIn("id", tmpl)
                self.assertIn("info", tmpl)
                self.assertIn("name", tmpl["info"])
                self.assertIn("severity", tmpl["info"])
                self.assertIn("payload_groups", tmpl)
                self.assertIn("matchers", tmpl)

    def test_severity_values(self):
        """severity는 정해진 값만 가질 수 있어야 함."""
        valid = {"critical", "high", "medium", "low", "info"}
        for tmpl in template_loader.load_all():
            sev = tmpl["info"]["severity"]
            self.assertIn(sev, valid, f"{tmpl['id']}: invalid severity '{sev}'")

    def test_payload_groups_have_payloads(self):
        """각 payload_group에 최소 1개의 페이로드가 있어야 함."""
        for tmpl in template_loader.load_all():
            for group in tmpl.get("payload_groups", []):
                with self.subTest(template=tmpl["id"], group=group.get("group")):
                    self.assertIn("payloads", group)
                    self.assertGreater(len(group["payloads"]), 0)

    def test_matchers_have_regex(self):
        """type: regex 매처는 regex 필드가 있어야 함."""
        for tmpl in template_loader.load_all():
            for matcher in tmpl.get("matchers", []):
                if matcher.get("type") == "regex":
                    with self.subTest(template=tmpl["id"], matcher=matcher.get("name")):
                        self.assertIn("regex", matcher)
                        self.assertGreater(len(matcher["regex"]), 0)

    def test_get_all_payloads_flattens(self):
        """get_all_payloads가 모든 그룹의 페이로드를 평탄화해야 함."""
        for tmpl in template_loader.load_all():
            flat = template_loader.get_all_payloads(tmpl)
            total = sum(len(g["payloads"]) for g in tmpl.get("payload_groups", []))
            self.assertEqual(len(flat), total)

    def test_compile_matchers_returns_compiled(self):
        """compile_matchers가 정규식을 컴파일하여 patterns 필드를 포함해야 함."""
        for tmpl in template_loader.load_all():
            compiled = template_loader.compile_matchers(tmpl)
            for m in compiled:
                self.assertIn("patterns", m)
                self.assertGreater(len(m["patterns"]), 0)

    def test_ssti_matcher_49(self):
        """SSTI 템플릿의 arithmetic_result_49 matcher가 올바르게 동작해야 함."""
        tmpl = template_loader.load_by_id("ssti-basic")
        self.assertIsNotNone(tmpl)
        compiled = template_loader.compile_matchers(tmpl)
        matcher = next((m for m in compiled if m["name"] == "arithmetic_result_49"), None)
        self.assertIsNotNone(matcher)

        # 양성 케이스
        self.assertTrue(any(p.search("Result: 49") for p in matcher["patterns"]))
        self.assertTrue(any(p.search("value=49 confirmed") for p in matcher["patterns"]))
        # 음성 케이스 (다른 숫자에 붙은 경우)
        self.assertFalse(any(p.search("value=149") for p in matcher["patterns"]))
        self.assertFalse(any(p.search("490ms") for p in matcher["patterns"]))

    def test_ssti_matcher_7777777(self):
        """SSTI 7777777 matcher 검증."""
        tmpl = template_loader.load_by_id("ssti-basic")
        compiled = template_loader.compile_matchers(tmpl)
        matcher = next((m for m in compiled if m["name"] == "string_multiplication_result"), None)
        self.assertIsNotNone(matcher)
        self.assertTrue(any(p.search("output: 7777777") for p in matcher["patterns"]))
        self.assertFalse(any(p.search("output: 77") for p in matcher["patterns"]))

    def test_load_by_id(self):
        """load_by_id가 올바른 템플릿만 반환해야 함."""
        tmpl = template_loader.load_by_id("sqli-basic")
        self.assertIsNotNone(tmpl)
        self.assertEqual(tmpl["id"], "sqli-basic")

        missing = template_loader.load_by_id("nonexistent-id")
        self.assertIsNone(missing)

    def test_matchers_condition_values(self):
        """matchers_condition은 or 또는 and여야 함."""
        for tmpl in template_loader.load_all():
            cond = tmpl.get("matchers_condition", "or")
            self.assertIn(cond, ["or", "and"], f"{tmpl['id']}: invalid condition '{cond}'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
