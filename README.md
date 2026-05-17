# 통합 웹 취약점 스캐너 v2.0

**Fingerprint → Crawl → Contextualize → Audit → Validate → Report**

CLI 대화형 모드와 FastAPI REST API 서버 모드를 하나의 코드베이스에서 지원합니다.

---

## 빠른 시작

```bash
pip install -r requirements.txt
cp .env.example .env

# CLI 대화형 모드
python main.py --cli

# CLI — URL 직접 지정
python main.py --cli --url http://testphp.vulnweb.com --depth 2 --pages 30

# FastAPI 서버 모드 (기본)
python main.py
# → http://localhost:8000/docs 에서 Swagger UI 확인
```

---

## 프로젝트 구조

```
├── main.py              # 통합 진입점 (--cli / --server)
├── requirements.txt
├── .env.example
│
├── api/                 # FastAPI 라우터
│   ├── scan.py          # POST/GET/DELETE /api/scan
│   └── reports.py       # GET /api/reports  + /{id}/html
│
├── engine/              # 핵심 스캔 엔진
│   ├── profiler/        # 핑거프린터 (서버·OS·언어·WAF·보안헤더)
│   ├── crawler/         # BFS 비동기 크롤러
│   ├── contextualizer/  # 파라미터별 페이로드 최적화
│   ├── auditor/         # 페이로드 주입 (HTML/JSON/GraphQL)
│   ├── mutator/         # WAF 우회 변종 생성
│   ├── validator/       # 오탐 제거 (베이스라인 비교)
│   └── templates/       # YAML 탐지 템플릿
│       ├── sqli.yaml
│       ├── xss.yaml
│       ├── ssti.yaml
│       ├── command_injection.yaml
│       ├── open_redirect.yaml
│       └── path_traversal.yaml
│
├── models/              # SQLAlchemy ORM + Pydantic 스키마
├── utils/               # 공통 유틸리티
│   ├── http_client.py   # 비동기 HTTP 클라이언트
│   ├── logger.py        # 통합 로거
│   └── reporter.py      # HTML / JSON 보고서 생성
├── worker/              # 백그라운드 스캔 파이프라인
└── tests/               # 단위 테스트
```

---

## 실행 모드

### CLI 모드

```bash
python main.py --cli [--url URL] [--depth N] [--pages N] [--verbose]
```

- 대화형 프롬프트 또는 인수로 스캔 설정
- `reports/scan_YYYYMMDD_HHMMSS/` 폴더에 **HTML + JSON** 보고서 자동 저장
- HTML 보고서: 다크 모드, 심각도 필터, 검색, PDF 저장 지원

### 서버 모드

```bash
python main.py [--server]
```

| 엔드포인트 | 설명 |
|---|---|
| `POST /api/scan` | 스캔 작업 생성 (백그라운드 실행) |
| `GET /api/scan/{id}` | 스캔 상태 + 결과 조회 (JSON) |
| `GET /api/reports/{id}/html` | HTML 보고서 (브라우저 직접 확인) |
| `GET /api/reports/templates` | 사용 가능한 템플릿 목록 |
| `GET /docs` | Swagger UI |

---

## 스캔 파이프라인

| 단계 | 모듈 | 설명 |
|---|---|---|
| 1 | `engine/profiler` | HTTP 헤더로 서버·OS·언어·WAF·보안 헤더 탐지 |
| 2 | `engine/crawler` | BFS 비동기 크롤링 (링크·폼 수집) |
| 3 | `engine/contextualizer` | 파라미터 타입 추론 + WAF 감지 시 페이로드 축소 |
| 4 | `engine/auditor` | YAML 템플릿 기반 페이로드 주입 (HTML/JSON/GraphQL) |
| 5 | `engine/mutator` | WAF 우회 변종 자동 생성 (8가지 전략) |
| 6 | `engine/validator` | 베이스라인 비교 오탐 제거 |

---

## 탐지 템플릿

| 템플릿 | 심각도 | 탐지 방식 |
|---|---|---|
| `sqli.yaml` | Critical | 에러 기반·불린·시간·유니온 SQLi |
| `ssti.yaml` | Critical | Jinja2·Twig·Spring EL·ERB·EJS |
| `xss.yaml` | High | 반사형 XSS (기본·필터 우회·DOM·이벤트) |
| `command_injection.yaml` | Critical | Linux/Windows OS 명령어 주입 |
| `path_traversal.yaml` | High | 경로 탐색 (Unix/Windows) |
| `open_redirect.yaml` | Medium | 외부 도메인 리다이렉트 |

---

## 법적 고지

이 도구는 **본인이 소유하거나 명시적 허가를 받은 시스템에서만** 사용하십시오.
무단 스캔은 법적 처벌을 받을 수 있습니다.
