# Vulnerability Scanner — Backend

FastAPI + SQLite 기반 웹 취약점 자동 스캔 백엔드.  
SSTI · SQLi · XSS 등 YAML 템플릿 기반으로 탐지 규칙을 추가/제거할 수 있습니다.

---

## 📁 디렉터리 구조

```
/backend
├── .env                          # 환경변수 (직접 수정)
├── .env.example                  # 환경변수 예시
├── README.md
├── requirements.txt
├── main.py                       # FastAPI 앱 엔트리포인트
│
├── /api
│   ├── scan.py                   # 스캔 CRUD 라우터
│   └── reports.py                # 보고서 조회 라우터
│
├── /worker
│   └── tasks.py                  # 비동기 스캔 파이프라인
│
├── /engine
│   ├── /profiler/fingerprint.py  # 기술 스택 & WAF 탐지
│   ├── /crawler/crawler.py       # URL 크롤링 & 입력 포인트 수집
│   ├── /auditor/auditor.py       # 페이로드 주입 & 응답 분석
│   ├── /validator/validator.py   # 오탐 제거 & 결과 검증
│   └── /templates/               # 취약점 탐지 YAML 규칙
│       ├── loader.py             # 동적 템플릿 로더
│       ├── ssti.yaml
│       ├── sqli.yaml
│       └── xss.yaml
│
├── /models
│   ├── database.py               # SQLite 연결 & 초기화
│   └── schemas.py                # ORM + Pydantic 스키마
│
├── /utils
│   ├── http_client.py            # 비동기 HTTP 클라이언트
│   └── logger.py                 # 로깅 설정
│
└── /tests
    ├── test_runner.py            # CLI 단독 실행 테스트
    └── test_templates.py         # 템플릿 유닛 테스트
```

---

## ⚡ 빠른 시작

### 1. 의존성 설치

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. 환경변수 설정

```bash
cp .env.example .env
# .env 파일을 열어 필요한 값 수정
```

주요 설정:

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `DATABASE_URL` | `sqlite:///./scanner.db` | SQLite 파일 경로 |
| `SCAN_TIMEOUT` | `30` | 요청 타임아웃 (초) |
| `SCAN_CONCURRENCY` | `5` | 동시 요청 수 |
| `SCAN_DELAY` | `0.5` | 요청 간 딜레이 (WAF 우회) |
| `LOG_LEVEL` | `INFO` | 로그 레벨 |

### 3. 서버 실행

```bash
python main.py
# 또는
uvicorn main:app --reload --port 8000
```

서버 기동 후 자동으로 `scanner.db` SQLite 파일이 생성됩니다.

---

## 🧪 프론트엔드 없이 백엔드 단독 검증

### 방법 1: CLI 테스트 러너

```bash
# 오프라인 데모 (HTTP 요청 없음 — 템플릿·매처 로직만 확인)
python tests/test_runner.py --demo

# 실제 URL 스캔
python tests/test_runner.py --url https://example.com

# 특정 템플릿만 사용
python tests/test_runner.py --url https://example.com --templates ssti-basic xss-basic
```

### 방법 2: 유닛 테스트

```bash
python tests/test_templates.py
# 또는 pytest
pip install pytest
pytest tests/test_templates.py -v
```

### 방법 3: Swagger UI (서버 실행 후)

```
http://localhost:8000/docs
```

주요 엔드포인트 직접 테스트 가능:
- `POST /api/scan` — 스캔 시작
- `GET /api/scan/{id}` — 결과 조회
- `GET /api/reports/templates` — 사용 가능한 템플릿 목록

### 방법 4: curl / httpie

```bash
# 스캔 시작
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "templates": ["ssti-basic"]}'

# 결과 조회 (위 응답의 id 사용)
curl http://localhost:8000/api/scan/{JOB_ID}

# 템플릿 목록 확인
curl http://localhost:8000/api/reports/templates
```

---

## 🗄️ 데이터베이스

**SQLite** (`scanner.db`)를 사용합니다. 별도 서버 설치 불필요.

- **VSCode**: SQLite Viewer 확장 설치 후 `scanner.db` 파일 바로 열기
- **Python**: 내장 `sqlite3` 모듈로 쿼리 가능

```python
import sqlite3
conn = sqlite3.connect("scanner.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM scan_jobs ORDER BY created_at DESC")
print(cursor.fetchall())
```

---

## 🧩 새 취약점 템플릿 추가

`engine/templates/` 디렉터리에 YAML 파일을 추가하면 **코드 수정 없이 자동 로드**됩니다.

```yaml
id: my-vuln-basic
info:
  name: "My Vulnerability"
  severity: high
  description: "설명"
  tags: [my-tag]

definition:
  method: [GET, POST]
  position: [query, body, form_field]

payload_groups:
  - group: group_name
    engine: "Engine Name"
    payloads:
      - "payload1"
      - "payload2"

matchers_condition: or

matchers:
  - type: regex
    name: matcher_name
    description: "매처 설명"
    regex:
      - "pattern_to_match"
```

---

## 🔌 API 엔드포인트 요약

| Method | Path | 설명 |
|--------|------|------|
| `GET` | `/` | 헬스체크 |
| `GET` | `/health` | 헬스체크 |
| `POST` | `/api/scan` | 스캔 시작 |
| `GET` | `/api/scan` | 스캔 목록 |
| `GET` | `/api/scan/{id}` | 스캔 상태 + 결과 |
| `DELETE` | `/api/scan/{id}` | 스캔 삭제 |
| `GET` | `/api/reports` | 완료된 보고서 목록 |
| `GET` | `/api/reports/{id}` | 보고서 상세 |
| `GET` | `/api/reports/templates` | 사용 가능한 템플릿 목록 |

---

## ⚠️ 주의사항

> 이 도구는 **본인이 소유하거나 명시적 테스트 허가를 받은 시스템에만** 사용하십시오.  
> 무단 스캔은 법적 책임이 따를 수 있습니다.
