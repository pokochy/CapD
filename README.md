# Web Vulnerability Scanner

통합 웹 취약점 스캐너 — CLI 모드와 API 서버 모드를 모두 지원합니다.

## 구조

```
├── backend/   # FastAPI 기반 REST API 서버 (Repo: V_Web_Scanner)
└── cli/       # 단독 실행 CLI 스캐너 (Repo: webscanner)
```

---

## backend/ — FastAPI 서버

> 원본: [Jannerf-43/V_Web_Scanner](https://github.com/Jannerf-43/V_Web_Scanner)

SQLite 데이터베이스와 REST API를 통해 스캔 작업을 관리하는 백엔드 서버입니다.

### 실행

```bash
cd backend
cp .env.example .env
pip install -r requirements.txt
python main.py
```

Swagger UI: http://localhost:8000/docs

### 지원 취약점 (템플릿)

| 템플릿 | 설명 |
|---|---|
| `sqli.yaml` | SQL Injection (error/boolean/time/union based) |
| `xss.yaml` | Reflected XSS (basic, filter bypass, DOM, event handler) |
| `ssti.yaml` | Server-Side Template Injection (Jinja2, Twig, Spring EL 등) |
| `command_injection.yaml` | OS Command Injection |
| `open_redirect.yaml` | Open Redirect |

### 파이프라인

1. **Fingerprinting** — 서버/WAF/기술스택 탐지
2. **Crawling** — BFS 기반 페이지/폼 수집
3. **Contextualizing** — 파라미터별 페이로드 최적화
4. **Auditing** — 페이로드 주입 (GraphQL/JSON/HTML 지원)
5. **Validation** — 오탐 제거 (베이스라인 비교)

---

## cli/ — CLI 스캐너

> 원본: [yws3267/webscanner](https://github.com/yws3267/webscanner)

대화형 CLI로 실행하는 독립형 스캐너입니다. HTML/JSON 리포트를 자동 생성합니다.

### 실행

```bash
cd cli
pip install -r requirements.txt
python main.py
```

### 지원 취약점 (템플릿)

| 템플릿 | 설명 |
|---|---|
| `templates/sqli.yaml` | SQL Injection |
| `templates/xss.yaml` | Reflected XSS |
| `templates/ssti.yaml` | SSTI |
| `templates/command_injection.yaml` | Command Injection |
| `templates/open_redirect.yaml` | Open Redirect |
| `templates/path_traversal.yaml` | Path Traversal |

### 파이프라인

1. **Fingerprinting** — HTTP 헤더 기반 기술스택/보안헤더 탐지
2. **Crawling** — aiohttp 비동기 BFS 크롤링
3. **Analyzing** — 주입 포인트 추출
4. **Scanning** — YAML 템플릿 기반 멀티스레드 스캔
5. **Reporting** — HTML/JSON 리포트 생성

---

## 법적 고지

이 도구는 **본인이 소유하거나 명시적 허가를 받은 시스템에서만** 사용하십시오.
