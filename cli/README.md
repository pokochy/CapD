# 🔍 통합 웹 취약점 스캐너 v2.0

HTTP 핑거프린팅 → 비동기 크롤링 → 주입 지점 분석 → YAML 템플릿 기반 스캔 → 보고서 생성까지 한 번에 실행하는 통합 웹 취약점 스캐너입니다.

> ⚠️ **본 도구는 보안 학습 및 본인 소유 시스템에 대한 테스트 목적으로만 사용하십시오.**  
> 허가되지 않은 시스템에 대한 스캔은 불법입니다.

---

## 📁 프로젝트 구조

```
scanner/
├── main.py            # 진입점 (대화형 실행)
├── pipeline.py        # 4단계 파이프라인 오케스트레이터
├── models.py          # 공통 데이터 모델 (dataclass)
├── fingerprinter.py   # HTTP 헤더 기반 기술 스택 핑거프린팅
├── crawler.py         # 비동기 웹 크롤러 (aiohttp)
├── analyzer.py        # 주입 지점 분석기
├── engine.py          # YAML 템플릿 기반 스캔 엔진
├── reporter.py        # 결과 보고서 생성 (콘솔 + JSON)
└── templates/
    ├── sqli.yaml           # SQL Injection
    ├── xss.yaml            # Reflected XSS
    └── path_traversal.yaml # Path Traversal
```

---

## ⚙️ 스캔 파이프라인

```
Phase 0   핑거프린팅     웹서버 / OS / 언어 / 프레임워크 / 보안 헤더 탐지
   ↓
Phase 1   크롤링         비동기 BFS 크롤러로 링크 / 폼 / 쿼리 파라미터 수집
   ↓
Phase 2   분석           크롤링 결과에서 주입 가능한 포인트(ScanTarget) 추출
   ↓
Phase 3   스캔           YAML 템플릿 × ScanTarget 멀티스레드 인젝션 스캔
   ↓
Phase 4   보고서         콘솔 출력 + scan_report.json 저장
```

---

## 📦 설치

### Python 버전

Python **3.10** 이상 권장

### 라이브러리 설치

```bash
pip install aiohttp beautifulsoup4 requests pyyaml urllib3
```

| 라이브러리       | 버전   | 용도                       |
| ---------------- | ------ | -------------------------- |
| `aiohttp`        | ≥ 3.9  | 비동기 HTTP 크롤러         |
| `beautifulsoup4` | ≥ 4.12 | HTML 파싱 (링크 / 폼 추출) |
| `requests`       | ≥ 2.31 | 동기 HTTP 스캔 요청        |
| `pyyaml`         | ≥ 6.0  | YAML 템플릿 로드           |
| `urllib3`        | ≥ 2.0  | HTTPS 인증서 경고 억제     |

또는 `requirements.txt` 로 한 번에 설치:

```bash
pip install -r requirements.txt
```

```
# requirements.txt
aiohttp>=3.9
beautifulsoup4>=4.12
requests>=2.31
pyyaml>=6.0
urllib3>=2.0
```

---

## 🚀 사용법

### 기본 실행

```bash
python main.py
```

실행하면 아래와 같이 대화형으로 설정을 입력합니다.

```
  스캔 URL [http://testphp.vulnweb.com]: http://example.com
  크롤링 깊이 (기본 2): 2
  최대 페이지 수 (기본 30): 30
  상세 로그 출력? (y/N): n
```

### 코드에서 직접 사용

```python
from pipeline import VulnScanPipeline

pipeline = VulnScanPipeline(
    target_url="http://testphp.vulnweb.com",
    template_dir="templates",
    max_depth=2,
    max_pages=30,
)
findings = pipeline.run()
```

### 핑거프린팅만 단독 실행

```python
from fingerprinter import fingerprint, print_fingerprint

result = fingerprint("http://example.com")
print_fingerprint(result)
```

### 각 모듈 단독 사용 예시

```python
from analyzer import Analyzer

analyzer = Analyzer()

# 방식 1: raw dict (기존 방식)
targets = analyzer.parse_request({
    "url": "http://example.com/page?id=1",
    "method": "GET",
    "headers": {"Cookie": "session=abc"},
    "body": None,
})

# 방식 2: 크롤러 결과 연동
# targets = analyzer.build_targets(crawled_pages)
```

---

## 📋 YAML 템플릿 작성법

`templates/` 폴더에 `.yaml` 파일을 추가하면 자동으로 로드됩니다.

```yaml
id: my-template

info:
  name: '취약점 이름'
  severity: 'critical' # critical / high / medium / low / info
  description: '설명'

# 공격을 수행할 조건 필터
definition:
  method:
    - GET
    - POST
  position:
    - query # URL ?param=value
    - body # POST form data
    - form_field # 크롤러가 발견한 <form> 필드
    - cookie # Cookie 헤더
    - header # 일반 HTTP 헤더

payloads:
  - '페이로드1'
  - '페이로드2'

matchers-condition: or # or | and

matchers:
  - type: word # 응답 본문 키워드 매칭
    words:
      - 'error keyword'
  - type: status # HTTP 상태 코드 매칭
    status:
      - 500
  - type: time # 응답 지연 시간 매칭 (초)
    delay: 5
```

---

## 📊 결과 보고서

스캔 완료 후 콘솔 출력과 함께 `scan_report.json` 이 생성됩니다.

```json
{
  "generated_at": "2025-01-01T12:00:00",
  "fingerprint": {
    "webserver": "Apache",
    "language": "PHP",
    "missing_security": ["X-Frame-Options", "Content-Security-Policy"]
  },
  "total_findings": 2,
  "findings": [
    {
      "vulnerability": "SQL Injection",
      "severity": "critical",
      "position": "query",
      "url": "http://example.com/page",
      "method": "GET",
      "inject_param": "id",
      "payload": "' OR 1=1--",
      "evidence": "sql syntax",
      "found_on": "http://example.com/page?id=1"
    }
  ]
}
```

---

## 🔧 주요 파라미터

| 파라미터            | 기본값 | 설명                       |
| ------------------- | ------ | -------------------------- |
| `max_depth`         | 2      | 크롤링 최대 깊이           |
| `max_pages`         | 50     | 크롤링 최대 페이지 수      |
| `crawl_concurrency` | 3      | 동시 크롤링 요청 수        |
| `scan_workers`      | 5      | 스캔 멀티스레드 수         |
| `request_delay`     | 0.3    | 크롤링 요청 간 딜레이 (초) |

---

## 📄 라이선스

본 프로젝트는 학습 목적으로 제작되었습니다. 허가된 환경에서만 사용하십시오.
