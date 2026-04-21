# 웹 취약점 스캐너 (Template-Based Web Vulnerability Scanner)

템플릿 기반 웹 취약점 스캐너입니다.  
YAML 템플릿에 페이로드와 탐지 조건을 정의하면 스캐너가 자동으로 HTTP 요청을 생성하고 응답을 분석합니다.  
비동기(asyncio + httpx) 구조로 빠른 스캔을 지원합니다.

---

## 프로젝트 구조

```
scanner/
├── main.py                     # CLI 진입점
├── requirements.txt
├── core/
│   ├── __init__.py
│   ├── models.py               # 데이터 모델 (ScanTarget, ScanResult 등)
│   ├── analyzer.py             # URL/폼에서 주입 지점 추출
│   ├── engine.py               # 비동기 스캔 엔진
│   ├── injector.py             # HTTP 요청에 페이로드 삽입
│   ├── matcher.py              # 응답 매처 평가
│   ├── template_loader.py      # YAML 템플릿 파싱·로드
│   ├── reporter.py             # 결과 출력 및 파일 저장
│   ├── validator.py            # 입력값 검증 (URL, rate, timeout)
│   └── logger.py               # 로깅 초기화
└── templates/
    ├── sqli/
    │   └── sql_injection_base.yaml
    ├── xss/
    │   └── xss_reflected.yaml
    ├── traversal/
    │   └── path_traversal_unix.yaml
    └── ssrf/
        └── ssrf_basic.yaml
```

---

## 설치 방법

### 요구사항
- Python 3.10 이상

### 설치

```bash
# 저장소 복제 또는 파일 다운로드
cd scanner/

# 의존성 설치
pip install -r requirements.txt
```

**requirements.txt**
```
httpx>=0.27.0
requests>=2.31.0
pyyaml>=6.0.1
```

---

## 사용법 (CLI)

### 기본 사용법

```bash
# URL 쿼리 파라미터 스캔 (모든 템플릿 사용)
python main.py --url "https://example.com/search?q=test"

# 특정 카테고리만 스캔
python main.py --url "https://example.com/?id=1" --category sqli

# 복수 카테고리 지정
python main.py --url "https://example.com/?q=test" --category xss --category sqli

# 단일 템플릿 파일 직접 지정
python main.py --url "https://example.com/?id=1" \
  --template templates/sqli/sql_injection_base.yaml
```

### POST 요청 스캔

```bash
# Form-encoded body
python main.py \
  --url "https://example.com/login" \
  --method POST \
  --body "username=admin&password=test" \
  --category sqli

# 추가 헤더 지정
python main.py \
  --url "https://example.com/api" \
  --method POST \
  --header "Authorization:Bearer token123" \
  --header "Content-Type:application/x-www-form-urlencoded" \
  --body "input=test"
```

### 결과 저장

```bash
# JSON 파일로 저장
python main.py --url "https://example.com/?q=test" \
  --output-json logs/result.json

# 텍스트 파일로 저장
python main.py --url "https://example.com/?q=test" \
  --output-txt logs/result.txt

# 로그 파일 저장 + 로그 레벨 지정
python main.py --url "https://example.com/?q=test" \
  --log-file logs/scan.log \
  --log-level DEBUG
```

### 성능 조절

```bash
# 초당 요청 수 제한 (기본: 5.0)
python main.py --url "https://example.com/?q=test" --rate 2.0

# 동시 요청 수 제한 (기본: 10)
python main.py --url "https://example.com/?q=test" --concurrency 5

# 타임아웃 설정 (기본: 10초)
python main.py --url "https://example.com/?q=test" --timeout 15
```

### 기타

```bash
# 사용 가능한 템플릿 목록 확인
python main.py --list-templates

# 특정 디렉터리의 템플릿 목록 확인
python main.py --list-templates --templates templates/

# 취약점 발견 시 나머지 페이로드 건너뜀
python main.py --url "https://example.com/?id=1" --stop-on-hit

# 콘솔 출력 최소화 (취약점만 표시)
python main.py --url "https://example.com/?id=1" --quiet
```

### 전체 옵션

```
옵션                     설명                              기본값
--url URL                스캔 대상 URL                      (필수)
--method METHOD          HTTP 메서드 GET/POST/PUT/PATCH      GET
--body BODY              요청 본문 (form-encoded 또는 JSON)  ""
--header KEY:VAL         추가 헤더 (여러 번 지정 가능)
--cookie KEY=VAL         쿠키 (여러 번 지정 가능)
--template FILE          단일 템플릿 YAML 파일 경로
--templates DIR          템플릿 디렉터리 (전체 로드)         templates/
--category CAT           로드할 카테고리 (여러 번 지정 가능)
--list-templates         템플릿 목록 출력 후 종료
--timeout SEC            HTTP 타임아웃 (초)                  10.0
--rate RPS               초당 요청 수 제한                   5.0
--concurrency N          최대 동시 요청 수                   10
--stop-on-hit            첫 취약점 발견 후 나머지 건너뜀
--output-json FILE       JSON 결과 저장 경로
--output-txt  FILE       텍스트 결과 저장 경로
--log-file FILE          로그 파일 저장 경로
--log-level LEVEL        DEBUG/INFO/WARNING/ERROR           INFO
--quiet                  콘솔 출력 최소화
```

### 종료 코드

| 코드 | 의미 |
|------|------|
| 0    | 스캔 완료, 취약점 없음 |
| 1    | 실행 오류 (잘못된 URL, 템플릿 없음 등) |
| 2    | 스캔 완료, **취약점 발견** (CI/CD 파이프라인 활용 가능) |

---

## 스캐너 동작 방식

```
[입력 URL + 옵션]
      │
      ▼
[Analyzer] — URL 쿼리·POST body·쿠키·헤더에서 주입 가능한 파라미터 추출
      │         → List[ScanTarget]
      ▼
[ScanEngine] — (target × template × payload) 조합을 비동기로 실행
      │         asyncio Semaphore로 동시 요청 수 제한
      │         rate limit으로 초당 요청 수 조절
      ▼
[Injector] — position(query/body/form_field/cookie/header/path)에 따라
      │       페이로드를 HTTP 요청에 삽입 → PreparedRequest
      ▼
[HTTP 요청] — httpx.AsyncClient로 비동기 전송
      ▼
[Matcher] — 응답을 템플릿 matchers[]로 평가
      │       word / regex / status / time / size / header
      ▼
[ScanResult] → Reporter(콘솔 요약 + JSON/텍스트 파일 저장)
```

### 주입 위치 (position)

| position | 설명 |
|----------|------|
| `query` | URL 쿼리 파라미터 (`?key=payload`) |
| `body` | POST 요청 본문 |
| `form_field` | HTML 폼 필드 (크롤러 연동 시) |
| `cookie` | Cookie 헤더 |
| `header` | 임의 HTTP 헤더 |
| `path` | URL 경로 내 `{param}` 플레이스홀더 |

---

## 템플릿 작성 방법

템플릿은 `templates/<카테고리>/` 디렉터리에 `.yaml` 파일로 저장합니다.

### 기본 구조

```yaml
id: 고유-ID                    # 결과 리포트에 표시되는 템플릿 식별자
info:
  name: '템플릿 이름'
  severity: 'critical'         # critical / high / medium / low / info
  description: '설명'

definition:
  method: ['GET', 'POST']      # 허용 HTTP 메서드
  position: ['query', 'body']  # 허용 주입 위치

payloads:
  - '페이로드1'
  - '페이로드2'

matchers-condition: or         # or: 하나라도 일치 / and: 모두 일치

matchers:
  - type: word                 # 응답 본문 키워드 검사
    words:
      - '에러 문자열1'
      - '에러 문자열2'

  - type: status               # HTTP 상태 코드 검사
    status: [200, 302]

  - type: regex                # 정규식 검사
    regex:
      - 'root:[x*]:0:0'

  - type: time                 # 응답 지연 검사 (초)
    delay: 5

  - type: size                 # 응답 크기 검사 (bytes)
    size: [1337]

  - type: header               # 응답 헤더 검사
    name: 'X-Powered-By'
    value: 'PHP'               # 생략하면 헤더 존재 여부만 확인
```

### matcher 공통 옵션

```yaml
matchers:
  - type: word
    words: ['keyword']
    condition: or              # 내부 복수 값 처리 방식 (기본: or)
    negate: true               # true이면 매치 결과를 반전
```

### 헤더 커스터마이즈

```yaml
headers:
  User-Agent: 'Mozilla/5.0'
  X-Forwarded-For: '127.0.0.1'
```

### 작성 예시 1 — 커스텀 에러 페이지 탐지

```yaml
id: error-page-detect
info:
  name: '에러 페이지 탐지'
  severity: 'low'
  description: '상세 에러 메시지 노출 탐지'

definition:
  method: ['GET']
  position: ['query']

payloads:
  - "'"
  - '"'
  - '--'

matchers-condition: or
matchers:
  - type: word
    words:
      - 'Stack Trace'
      - 'Exception in thread'
      - 'Traceback (most recent call last)'
  - type: regex
    regex:
      - 'line \d+ in <module>'
```

### 작성 예시 2 — 특정 헤더 탐지 (정보 노출)

```yaml
id: info-disclosure-header
info:
  name: '서버 정보 노출 헤더 탐지'
  severity: 'info'
  description: 'Server, X-Powered-By 헤더 노출 여부 확인'

definition:
  method: ['GET']
  position: ['query']

payloads:
  - 'test'

matchers-condition: or
matchers:
  - type: header
    name: 'X-Powered-By'
  - type: header
    name: 'Server'
    value: 'Apache'
```

---

## 템플릿 수정 방법

### 기존 페이로드 추가

```yaml
payloads:
  - "기존 페이로드1"
  - "기존 페이로드2"
  - "새로 추가할 페이로드"   # ← 이 줄 추가
```

### 새 매처 타입 추가 (코드 수정)

`core/matcher.py` 내 `_EVALUATORS` 딕셔너리에 함수를 등록합니다.

```python
def _eval_custom(defn, resp, elapsed):
    # 평가 로직 작성
    hit = ...
    return MatcherResult(hit=hit, mtype="custom", detail=[])

_EVALUATORS["custom"] = _eval_custom
```

### 새 주입 위치 추가 (코드 수정)

`core/injector.py` 내 `_INJECTORS` 딕셔너리에 함수를 등록합니다.

```python
def _inject_custom(url, param, payload, extra, headers):
    # PreparedRequest 생성 로직
    return requests.Request(...).prepare()

_INJECTORS["custom_position"] = _inject_custom
```

---

## 보안 주의사항

- 이 도구는 **본인이 소유하거나 명시적 허가를 받은 시스템**에만 사용하세요.
- 내부 IP(10.x, 192.168.x, 127.x 등)에 대한 스캔은 기본 차단됩니다.
- `--rate` 옵션으로 대상 서버에 과부하를 주지 않도록 조절하세요.
- 무단 취약점 스캔은 법적 책임이 따를 수 있습니다.
#