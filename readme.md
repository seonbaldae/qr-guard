> **계약 주의:** 이 스냅샷은 최신 Google Safe Browsing v5 단독 계약 이전의 OpenPhish 구현이며,
> Google 이전은 별도 작업으로 남아 있습니다. 따라서 현재 P0 계약을 완전히 충족하지 않습니다.

# QR Guard — FastAPI integration

기존 `app/precheck/` 정적 분석을 공개 API에 연결한 해커톤용 단일 프로세스 서버입니다.
실제 프론트와 C의 Docker/Playwright Worker는 이 변경에 포함되지 않습니다.
응답 예시는 성공한 분석으로 위장하지 않습니다. 피드가 없으면 OpenPhish는 `failed/matched:null`,
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

## 정적 분석 / 피드

`app/static_adapter.py`가 B의 `analyze(url)`을 호출하므로 기존 분석 파일은 수정하지 않았습니다.
OpenPhish는 `QR_GUARD_OPENPHISH_FILE`이 가리키는 신뢰할 수 있는 로컬 TXT 스냅샷만 읽습니다.
네트워크에서 자동 다운로드하지 않습니다. 전체 정규화 URL을 정확히 비교하며 호스트만 비교하지 않습니다.
피드는 앱 생성 시 읽으므로 파일을 교체했다면 서버를 재시작하세요.
빈 파일·잘못된 데이터·읽기 오류는 `failed`, 수정 시각이 24시간을 넘긴 피드는 `stale`입니다.
미탐지·피드 실패·주소 구조 신호 없음은 안전 보장이 아닙니다.

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

판정 우선순위는 알려진 피드 일치 → 브랜드 불일치와 관찰된 비밀번호 필드 조합 →
필요 검사 완료 시 범위 내 미탐지 → 그 외 확인 불가입니다. 요청 URL이 피드에 일치하면 Worker는 호출하지 않습니다.
Worker 완료 후 최종 도착 URL도 피드와 비교하며, 일치해도 실제 완료된 sandbox와 스크린샷 상태는 유지합니다.
네이버 도메인 매핑 출처: https://www.navercorp.com/service/portal 의 공식 `https://www.naver.com/` 링크.

## 검증 범위와 남은 작업

- 기존 정적 분석 테스트와 공개 API·F1/F2/F3 동작·오류 처리·CORS·allowlist·PNG 검사 테스트가 있습니다.
- API 테스트의 Worker 응답과 피드 파일은 **명시적인 테스트 데이터**입니다. 실제 탐지·실제 피드 성공을 의미하지 않습니다.
- 실제 Uvicorn HTTP 검사로 생성·조회·입력 오류·미연결 Worker 차단을 확인합니다.
- 실제 C Worker와 프론트가 도착하면 접속 주소/CORS 설정을 맞추고,
  **D1: Shadow DOM 비밀번호 관찰 → 브랜드 불일치 근거 → suspicious → 실제 PNG 조회**를 E2E로 검증해야 합니다.
- D1 실브라우저 검증, 네트워크 격리 검증, 실제 프론트 연동은 아직 완료하지 않았습니다.