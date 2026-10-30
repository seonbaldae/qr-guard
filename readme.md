# QR Guard — FastAPI integration

기존 `app/precheck/` 정적 분석을 공개 API에 연결한 해커톤용 단일 프로세스 서버입니다.
실제 프론트와 C의 Docker/Playwright Worker는 이 변경에 포함되지 않습니다.
정적 위협 조회는 Google Safe Browsing v5 단독입니다. API 키가 없거나 조회가 실패하면 `failed/matched:null`,
Worker가 미연결이면 sandbox는 `blocked`, 최종 판정은 `unknown`입니다.

## 실행 / 테스트

Python 3.11 이상이 필요합니다. 저장소 루트에서:

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

Swagger: `http://127.0.0.1:8000/docs`, OpenAPI: `/openapi.json`.
메모리 저장소이므로 반드시 **프로세스 1개**로 실행합니다. 재시작하면 검사 결과와 PNG가 사라집니다.
인증·영구 보관·운영 환경 배포 설정은 제공하지 않으므로 공개 인터넷에 그대로 노출하지 마세요.

## 프론트 연결 계약

| 요청 | 결과 |
|---|---|
| `POST /api/scans` | 202 `{scanId,status:"queued",mode}` |
| `GET /api/scans/{scanId}` | 200 camelCase ScanReport, 없는 ID는 404 |
| `GET /api/scans/{scanId}/screenshot` | 준비된 경우 200 image/png, 미준비·실패는 409, 없는 ID는 404 |
| `GET /api/health` | 프로세스 생존 확인만 수행 |

생성 요청:

```json
{"url":"https://example.com/","source":"qr","mode":"sandbox","expectedBrand":"naver"}
```

- `source` 기본값은 `qr`, `mode` 기본값은 `static`입니다. **QR UI는 `sandbox`를 명시해야 합니다.**
- `expectedBrand`는 선택 값이며 현재 검증된 브랜드 ID는 `naver`입니다. 모르는 ID를 추측하지 않습니다.
- `status`가 `completed/failed`일 때까지 결과를 조회합니다. `completed`와 안전 판정은 다릅니다.
- 화면은 `verdict.level`의 `malicious/suspicious/no_known_threat/unknown`을 구분해야 합니다.
- 스크린샷은 `screenshot.available=true`일 때만 요청합니다. 반환된 HTML/JS를 실행하지 않습니다.
- 취소 API·WebSocket·자동 목적지 열기는 구현하지 않습니다.
- CORS는 기본적으로 타 출처를 허용하지 않습니다. 프론트 주소가 정해지면
  `QR_GUARD_CORS_ORIGINS=http://localhost:5173`처럼 정확한 origin을 설정합니다.
  여러 origin은 쉼표로 구분하며 `*`와 쿠키 인증은 사용하지 않습니다.

## 정적 분석 / Google Safe Browsing v5

`app/static_adapter.py`가 B의 `analyze(url, check)` 결과를 공개 응답으로 변환합니다.
Google의 providers·signals·evidence를 보존하며 OpenPhish로 덮어쓰지 않습니다.
서버에서 `GOOGLE_SAFE_BROWSING_API_KEY`를 설정하세요. 키를 프론트·URL·로그·Git에 넣지 마세요.
기존 `SAFE_BROWSING_API_KEY`와 로컬 `.env` 읽기는 호환용으로만 유지합니다.
명시적으로 빈 `GOOGLE_SAFE_BROWSING_API_KEY`를 설정하면 호환 키와 파일을 읽지 않고 조회를 비활성화합니다.

조회는 httpx로 `GET https://safebrowsing.googleapis.com/v5/urls:search`에 한 URL을 전송합니다.
200의 비어 있지 않은 `threats`는 알려진 위협, 빈 `threats`는 검사 범위 내 미탐지입니다.
키 누락·401/403/429/5xx·타임아웃·비정상 응답은 미탐지가 아닌 `failed/matched:null`입니다.
성공한 양성·음성 결과는 Google의 `cacheDuration` 동안만 제한된 메모리 캐시에 보관합니다.
캐시와 진행 중 조회는 합쳐서 512건으로 제한합니다. 만료 전 항목을 삭제하는 대신,
포화 상태의 새 URL이나 동일 URL의 동시 조회는 외부 호출 없이 `failed/matched:null`로 처리합니다.
만료된 슬롯은 다시 사용하며, 실패한 조회는 캐시에 보관하지 않습니다.
Google은 호스트 접미사·경로 접두사 표현식을 검사하므로 결과를 **정확한 URL 일치**라고 표현하지 않습니다.

**개인정보·이용 조건:** 쿼리 등을 포함한 검사 URL이 Google에 전송됩니다. 프론트는 전송 전에 이를 고지해야 합니다.
실제 인증 토큰·개인정보가 포함된 URL은 시연에 사용하지 마세요. API 응답 근거에는 URL·키 원문을 기록하지 않습니다.
Safe Browsing은 비상업적 사용 조건과 경고·출처 표시 요구사항을 검토해야 하며,
미탐지는 Google 또는 우리 서비스의 안전 보장이 아닙니다.
참고: https://developers.google.com/safe-browsing/reference/rest/v5/urls/search

## C Worker 연결

`app/worker.py`는 실제 내부 HTTP 호출 어댑터입니다. Worker 서비스 자체가 아닙니다.
다음 설정을 모두 충족하기 전에는 호출하지 않습니다.

| 환경 변수 | 설명 |
|---|---|
| `QR_GUARD_WORKER_URL` | 신뢰하는 내부 Worker origin. 예: `http://worker:8001` |
| `QR_GUARD_DEMO_ORIGINS` | 별도로 통제하는 데모 사이트의 정확한 origin 목록 |
| `QR_GUARD_WORKER_EGRESS_VERIFIED` | 실제 네트워크 격리 검증 후에만 `true` |
| `QR_GUARD_MAX_SCANS` | 메모리 보관 상한. 기본 100건, 초과 생성은 503 |
| `QR_GUARD_WORKER_CONCURRENCY` | 동시 Worker 호출 상한. 기본 2건 |

어댑터는 `POST /internal/analyze`로 `{scanId,url,timeoutMs}`를 전달합니다.
반환되는 `finalUrl/httpStatus/pageTitle/passwordFieldCount/sensitiveFieldTypes/forms/requestHosts/redirected/screenshotBase64/limitations`
형태는 공용 API 명세를 따릅니다. 기본 timeout은 20초이고, HTTP redirect를 따라가지 않으며
환경 프록시를 상속하지 않습니다. 응답은 6 MiB, PNG는 4 MiB·1600만 픽셀 이내로 제한하고 PNG 형식을 검증합니다.
PNG는 청크 검사뿐 아니라 실제 픽셀 디코딩도 수행합니다. Worker가 보고한 CAPTCHA·DOM 관찰 제한은
URL·토큰 원문 없이 제한된 사유 범주로 전달합니다. 보관 상한 도달 시 자동 삭제하지 않으므로 데모를 재시작해야 합니다.

**이 origin 검사는 네트워크 방화벽이 아닙니다.** C가 redirect·DNS rebinding·하위 리소스까지
실제 네트워크 egress를 제한하는지 확인해야 합니다. 플래그만 켜는 것으로 격리가 구현되지 않습니다.
임의 악성 사이트를 방문하거나 실제 인증정보 입력·폼 제출을 수행하지 마세요.

판정 우선순위는 Google의 알려진 위협 탐지 → 브랜드 불일치와 관찰된 비밀번호 필드 조합 →
필요 검사 완료 시 범위 내 미탐지 → 그 외 확인 불가입니다. 요청 URL의 위협이 확인되면 Worker는 호출하지 않습니다.
Worker 완료 후 최종 도착 URL도 Google에 확인하며, 위협이 발견돼도 실제 완료된 sandbox와 스크린샷 상태는 유지합니다.
네이버 도메인 매핑 출처: https://www.navercorp.com/service/portal 의 공식 `https://www.naver.com/` 링크.

## 검증 범위와 남은 작업

- 기존 정적 분석 테스트와 공개 API·F1/F2/F3 동작·오류 처리·CORS·allowlist·PNG 검사 테스트가 있습니다.
- API 테스트의 Google·Worker 응답은 **명시적인 테스트 데이터**입니다. 실제 외부 Google 조회 성공을 의미하지 않습니다.
- 실제 Uvicorn HTTP 검사로 생성·조회·입력 오류·미연결 Worker 차단을 확인합니다.
- 실제 C Worker와 프론트가 도착하면 접속 주소/CORS 설정을 맞추고,
  **D1: Shadow DOM 비밀번호 관찰 → 브랜드 불일치 근거 → suspicious → 실제 PNG 조회**를 E2E로 검증해야 합니다.
- D1 실브라우저 검증, 네트워크 격리 검증, 실제 프론트 연동은 아직 완료하지 않았습니다.