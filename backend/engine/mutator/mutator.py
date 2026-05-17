"""
engine/mutator/mutator.py
──────────────────────────
3단계 (신규): Dynamic Mutation 엔진

고정 페이로드를 그대로 사용하면 WAF 시그니처에 즉시 차단된다.
Mutator는 런타임에 원본 페이로드를 여러 변종(mutation)으로 변환하여
WAF 탐지 확률을 낮춘다.

변환 전략 (MutationStrategy)
─────────────────────────────
1. IdentityStrategy      — 원본 그대로 (베이스라인)
2. CaseVariantStrategy   — 키워드 케이스 무작위 변환 (SELECT → SeLeCt)
3. CommentObfuscation    — SQL 주석 삽입 (OR → O/**/R)
4. WhitespaceVariant     — 공백을 탭·개행·URL인코딩으로 치환
5. HexEncoding           — 숫자 리터럴을 16진수로 변환 (1 → 0x1)
6. DoubleUrlEncoding     — 특수문자 이중 URL 인코딩
7. HtmlEntityEncoding    — HTML 엔티티 인코딩 (< → &#60;)
8. UnicodeNormalization  — 유사 유니코드 문자로 치환 (a → а [키릴])

사용 방법
─────────
mutator = Mutator()

# 단일 페이로드 변종 생성
variants = mutator.mutate("' OR 1=1 --", vuln_type="sqli", waf_detected=True)
# → ["' OR 1=1 --", "' oR 1=1 --", "'/**/OR/**/1=1/**/--", ...]

# 페이로드 리스트 전체에 적용
all_variants = mutator.mutate_all(payloads, vuln_type="sqli", waf_detected=True)
"""

from __future__ import annotations

import os
import random
import re
import urllib.parse
from abc import ABC, abstractmethod

from utils.logger import get_logger

logger = get_logger("mutator")

# WAF 탐지 시 변종 수, 미탐지 시 변종 수
_WAF_VARIANTS = int(os.getenv("MUTATOR_WAF_VARIANTS", "6"))
_NORMAL_VARIANTS = int(os.getenv("MUTATOR_NORMAL_VARIANTS", "2"))


# ── 전략 기반 클래스 ────────────────────────────────────────────────────────────

class MutationStrategy(ABC):
    name: str = "base"

    @abstractmethod
    def apply(self, payload: str) -> str: ...

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        return True


# ── 전략 구현 ────────────────────────────────────────────────────────────────

class IdentityStrategy(MutationStrategy):
    """원본 페이로드를 변경하지 않고 반환."""
    name = "identity"

    def apply(self, payload: str) -> str:
        return payload


class CaseVariantStrategy(MutationStrategy):
    """SQL/HTML 키워드의 케이스를 무작위로 변환."""
    name = "case_variant"

    # 대상 키워드 (SQLi, XSS 공통)
    _SQL_KEYWORDS = re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|AND|OR|NOT|"
        r"NULL|TABLE|ORDER|BY|HAVING|GROUP|LIMIT|OFFSET|EXEC|EXECUTE|CAST|"
        r"CONVERT|SLEEP|WAITFOR|DELAY|INFORMATION_SCHEMA)\b",
        re.IGNORECASE,
    )

    def apply(self, payload: str) -> str:
        def _randomize(m: re.Match) -> str:
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in m.group()
            )
        return self._SQL_KEYWORDS.sub(_randomize, payload)

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        return vuln_type in ("sqli", "xss")


class CommentObfuscationStrategy(MutationStrategy):
    """SQL 키워드 사이에 인라인 주석 /**/ 삽입."""
    name = "comment_obfuscation"

    _SPACES = re.compile(r" ")

    def apply(self, payload: str) -> str:
        # 공백의 절반을 /**/ 로 교체
        parts = payload.split(" ")
        result: list[str] = []
        for i, part in enumerate(parts):
            result.append(part)
            if i < len(parts) - 1:
                result.append("/**/" if random.random() > 0.4 else " ")
        return "".join(result)

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        return vuln_type == "sqli" and " " in payload


class WhitespaceVariantStrategy(MutationStrategy):
    """공백을 탭·개행·URL인코딩으로 치환."""
    name = "whitespace_variant"

    _ALTERNATIVES = ["\t", "\n", "%09", "%0a", "%20", "+"]

    def apply(self, payload: str) -> str:
        alt = random.choice(self._ALTERNATIVES)
        return payload.replace(" ", alt)

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        return " " in payload


class HexEncodingStrategy(MutationStrategy):
    """숫자 리터럴을 16진수 표현으로 변환 (1 → 0x1)."""
    name = "hex_encoding"

    _NUMBERS = re.compile(r"\b([1-9][0-9]*)\b")

    def apply(self, payload: str) -> str:
        def to_hex(m: re.Match) -> str:
            return hex(int(m.group()))
        return self._NUMBERS.sub(to_hex, payload)

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        return vuln_type == "sqli" and bool(re.search(r"\b[0-9]+\b", payload))


class DoubleUrlEncodingStrategy(MutationStrategy):
    """특수문자를 이중 URL 인코딩 (%27 → %2527)."""
    name = "double_url_encoding"

    # 한 번 URL 인코딩 후, % 를 다시 %25 로 인코딩
    def apply(self, payload: str) -> str:
        once = urllib.parse.quote(payload, safe="")
        return once.replace("%", "%25")

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        # 특수문자가 포함된 payload에만 적용
        return bool(re.search(r"[<>\"'&;=()\[\]{}]", payload))


class HtmlEntityEncodingStrategy(MutationStrategy):
    """HTML 특수문자를 엔티티로 변환 (< → &#60;)."""
    name = "html_entity_encoding"

    _CHAR_MAP = {
        "<": "&#60;",
        ">": "&#62;",
        '"': "&#34;",
        "'": "&#39;",
        "&": "&#38;",
        "/": "&#47;",
        "(": "&#40;",
        ")": "&#41;",
    }

    def apply(self, payload: str) -> str:
        return "".join(self._CHAR_MAP.get(c, c) for c in payload)

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        return vuln_type == "xss" and bool(
            re.search(r"[<>\"'&/()]", payload)
        )


class UnicodeNormalizationStrategy(MutationStrategy):
    """
    알파벳 일부를 시각적으로 유사한 유니코드 문자로 치환.
    WAF 시그니처 매칭을 혼란시킬 수 있다.
    """
    name = "unicode_normalization"

    # 시각적으로 유사한 유니코드 치환 맵 (라틴 → 키릴·기타)
    _LOOKALIKE: dict[str, str] = {
        "a": "\u0430",  # Cyrillic а
        "e": "\u0435",  # Cyrillic е
        "o": "\u043e",  # Cyrillic о
        "p": "\u0440",  # Cyrillic р
        "c": "\u0441",  # Cyrillic с
        "x": "\u0445",  # Cyrillic х
    }

    def apply(self, payload: str) -> str:
        result: list[str] = []
        for ch in payload:
            if ch.lower() in self._LOOKALIKE and random.random() > 0.6:
                sub = self._LOOKALIKE[ch.lower()]
                result.append(sub.upper() if ch.isupper() else sub)
            else:
                result.append(ch)
        return "".join(result)

    def is_applicable(self, payload: str, vuln_type: str) -> bool:
        # SSTI·XSS 키워드 기반 페이로드에만 제한적 적용
        return vuln_type in ("ssti", "xss") and bool(re.search(r"[a-zA-Z]{3,}", payload))


# ── Mutator 메인 클래스 ──────────────────────────────────────────────────────

class Mutator:
    """
    등록된 MutationStrategy를 순차 적용해 페이로드 변종을 생성한다.
    WAF 탐지 여부와 취약점 타입에 따라 적용할 전략과 변종 수를 조절한다.
    """

    _STRATEGIES: list[MutationStrategy] = [
        IdentityStrategy(),
        CaseVariantStrategy(),
        CommentObfuscationStrategy(),
        WhitespaceVariantStrategy(),
        HexEncodingStrategy(),
        DoubleUrlEncodingStrategy(),
        HtmlEntityEncodingStrategy(),
        UnicodeNormalizationStrategy(),
    ]

    def mutate(
        self,
        payload: str,
        vuln_type: str = "generic",
        waf_detected: bool = False,
    ) -> list[str]:
        """
        단일 페이로드에 대한 변종 리스트를 반환한다.
        항상 원본(Identity)이 첫 번째로 포함된다.

        파라미터:
          payload      : 원본 페이로드 문자열
          vuln_type    : "sqli" | "ssti" | "xss" | "generic"
          waf_detected : True면 더 많은 변종 생성
        """
        max_variants = _WAF_VARIANTS if waf_detected else _NORMAL_VARIANTS

        applicable = [
            s for s in self._STRATEGIES
            if s.is_applicable(payload, vuln_type)
        ]

        variants: list[str] = [payload]  # identity는 항상 포함
        seen: set[str] = {payload}

        for strategy in applicable[1:]:          # identity 제외한 전략 순회
            if len(variants) >= max_variants:
                break
            try:
                mutated = strategy.apply(payload)
                if mutated and mutated not in seen:
                    variants.append(mutated)
                    seen.add(mutated)
                    logger.debug(
                        f"[Mutator] {strategy.name} | "
                        f"{payload!r:.40} → {mutated!r:.40}"
                    )
            except Exception as exc:
                logger.warning(f"[Mutator] Strategy {strategy.name} failed: {exc}")

        return variants

    def mutate_all(
        self,
        payloads: list[dict],
        vuln_type: str = "generic",
        waf_detected: bool = False,
    ) -> list[dict]:
        """
        payload_groups 형식의 페이로드 리스트 전체에 mutation을 적용한다.

        입력 형식:  [{"payload": str, "group": str, "engine": str}, ...]
        반환 형식:  동일 구조 + {"mutated": True, "strategy": str} 필드 추가
        """
        result: list[dict] = []
        for item in payloads:
            original = item["payload"]
            variants = self.mutate(original, vuln_type=vuln_type, waf_detected=waf_detected)

            for i, variant in enumerate(variants):
                strategy_name = "identity" if i == 0 else self._STRATEGIES[min(i, len(self._STRATEGIES)-1)].name
                result.append({
                    **item,
                    "payload": variant,
                    "mutated": variant != original,
                    "strategy": strategy_name,
                    "original_payload": original,
                })
        return result
