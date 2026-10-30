# 프런트엔드 API 연결 안내

프런트엔드는 빌드 없이 정적 서버에서 실행합니다. 기본 동작은 실제 API 모드입니다. 기본 연결 방식은 Python 백엔드(`app/main.py`, API 계약 v0.2)의 `POST /api/scans` + `GET /api/scans/{id}` 폴링입니다. 어댑터(`src/services/response-adapter.js`)가 백엔드의 중첩 보고서를 아래 화면용 모델로 변환합니다. 신고 API는 백엔드에 아직 없습니다. 이 문서의 `/api/analyze`와 신고 경로는 제안 계약이며, 실제 백엔드 계약이 바뀌면 `src/config.js`와 어댑터에서 대응합니다.

QR·수동 입력의 `www.example.test/path` 같은 프로토콜 없는 웹 주소는 입력 단계에서 `https://www.example.test/path`로 정규화한 뒤 API에 보냅니다. 명시한 `http://`는 유지합니다. 이 보완은 사용자 입력에만 적용하며, API 응답의 주소와 실제 접속 목적지는 명시적인 HTTP(S) URL인지 계속 검증합니다. URL이 아닌 QR은 촬영 화면에 오류를 표시하고 수동 입력창으로 포커스를 옮기지 않습니다.

## 백엔드와 로컬 연결

```sh
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1   # 터미널 1: 백엔드
node scripts/dev-server.mjs                                              # 터미널 2: 프런트 + /api 전달
```

`http://127.0.0.1:8080/`을 엽니다. `scripts/dev-server.mjs`는 정적 파일을 서빙하고 `/api/*`를 백엔드(`QR_GUARD_API`, 기본 `http://127.0.0.1:8000`)로 전달하므로 브라우저에는 한 출처로 보여 CORS 설정이 필요 없습니다. Node.js 기본 기능만 사용하며 Vercel 정적 출력에는 포함되지 않습니다.

백엔드 보고서 변환 규칙:

| 백엔드 | 화면용 모델 |
| --- | --- |
| `status: queued` | `pending` (폴링 계속) |
| `verdict.level`: `malicious` / `suspicious` / `no_known_threat` / `unknown` | `phishing` / `suspicious` / `clear` / `inconclusive`. `verdict: null`·알 수 없는 값은 `inconclusive` |
| `mode: sandbox`에서 `sandboxAnalysis.status`가 `completed`가 아닌 `no_known_threat` | `inconclusive`로 낮춤 (격리 방문 없이는 정상으로 보지 않음) |
| `sandboxAnalysis.finalUrl` | `finalUrl` |
| `sandboxAnalysis.screenshot`이 `ready`이고 `available: true` | `previewUrl = /api/scans/{id}/screenshot` (아니면 `null`) |
| `staticAnalysis.providers` | `providers` |
| `staticAnalysis.signals` + `sandboxAnalysis.signals` | `signals` |
| 세 단계의 `limitations` | 중복을 제거해 합침 |
| `updatedAt` | `checkedAt` |
| 신고 건수·이력 | 백엔드가 제공하지 않으므로 `null`(확인할 수 없음) |

검사 요청은 `{ url, mode: "sandbox" }`를 보냅니다(`src/config.js`의 `scanMode`). 백엔드 기본값은 `static`입니다.

## 실행과 모드

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

`http://127.0.0.1:8080/`에서 프런트를 엽니다. 정적 서버에는 검사·신고 API가 없으므로 URL을 실제 검사하면 연결 오류가 표시됩니다. 화면의 데모 체험을 선택하면 미리 준비한 로컬 응답으로 3단계 화면을 볼 수 있습니다. 데모는 실제 사이트 접속·판정·신고 접수를 수행하지 않고 사이트 열기도 비활성화합니다. API 오류가 데모 성공으로 자동 전환되는 동작은 없습니다.

카메라 QR 인식은 브라우저의 `BarcodeDetector` 및 `qr_code` 형식 지원과 보안 컨텍스트가 필요합니다. 지원하지 않는 환경에서도 URL 직접 입력과 데모 체험을 이용할 수 있습니다. 휴대전화에서 일반 HTTP LAN 주소로 열면 카메라를 사용할 수 없으므로 HTTPS 환경에서 확인해야 합니다.

## 설정

`src/config.js`의 `frontendConfig`가 유일한 엔드포인트 설정입니다.

- `apiBaseUrl`: 기본 `''`로 프런트와 같은 출처입니다. 개발용 별도 백엔드가 필요하면 해당 HTTP(S) 출처를 명시합니다. 이 경우 백엔드의 CORS 설정이 필요합니다. 비밀값을 설정에 넣지 않습니다.
- `scanTransport`: 기본 `'job'`(Python 백엔드의 작업 생성·폴링). 한 번에 응답하는 서버는 `'direct'`로 바꿉니다.
- `scanMode`: 작업 생성 본문의 `mode`, 기본 `'sandbox'`입니다.
- `analyzePath`: 직접 검사 요청의 기본 경로 `/api/analyze`입니다.
- `createScanPath`, `scanPath`, `reportPath`: 작업 생성·조회·신고의 제안 경로입니다.
- `requestTimeoutMs`: 전체 검사·신고 요청의 제한 시간, 기본 30초입니다. 작업 폴링도 전체 제한 시간을 공유합니다.
- `pollIntervalMs`: 작업 상태 조회 간격, 기본 1.2초입니다.

요청은 `/api/` 경로의 설정된 백엔드 출처로만 전송되며 리다이렉트를 따르지 않습니다. 대상 URL은 검사 요청의 JSON 본문에만 포함됩니다. 카메라 영상·QR 이미지·브라우저 자격 증명은 보내지 않습니다. 같은 출처의 API는 브라우저 기본 세션 쿠키가 필요할 수 있어 `credentials: 'same-origin'`을 사용하지만 사용자 검사 결과를 별도 쿠키·저장소에 기록하지 않습니다.

## 직접 검사 응답

`POST /api/analyze`

```json
{ "url": "https://example.test/survey" }
```

완료 응답 예시:

```json
{
  "scanId": "scan-123",
  "requestedUrl": "https://example.test/survey",
  "finalUrl": "https://example.test/survey",
  "status": "completed",
  "verdict": "clear",
  "screenshotUrl": "/api/scans/scan-123/screenshot",
  "reportCount": 0,
  "isReported": false,
  "reportedByUser": false,
  "signals": [],
  "evidence": [],
  "providers": [{ "name": "위협 목록", "status": "checked", "matched": false, "checkedAt": "2026-10-31T00:00:00Z" }],
  "limitations": ["검사 범위 내 위협 미탐지는 완전한 안전 보증이 아닙니다."],
  "checkedAt": "2026-10-31T00:00:00Z"
}
```

- `requestedUrl`은 현재 검사 URL과 정규화 후 일치해야 합니다. 다르면 응답을 거부합니다.
- `status`는 `pending`, `running`, `completed`, `failed`, `blocked`, `skipped`, `cancelled`를 구분합니다. 직접 응답이 아직 진행 중이면 완료 결과로 표시하지 않습니다.
- `verdict`는 `clear`(또는 `normal`), `phishing`, `suspicious`, `inconclusive`를 지원합니다. 알 수 없거나 누락된 판정은 확인 불가입니다. 정적 분석의 `status: completed` 또는 빈 `signals`만으로 정상 판정을 만들지 않습니다.
- 사이트 진입은 **완료된 명시적 정상 판정**에서만 허용합니다. 유효하지 않은 최종 URL은 정상 판정을 보류하고 접속을 제공하지 않습니다. `finalUrl: null`인 정상 완료 결과는 원본 주소와 최종 목적지 미확인 안내를 사용합니다.
- `screenshotUrl`은 같은 백엔드 출처의 `/api/scans/<id>/screenshot`(선택적 png·jpg·jpeg·webp 확장자) 또는 `/api/screenshots/` 아래 경로만 허용합니다. 서버는 이 경로에서 이미지 바이트만 응답하고 외부 리다이렉트·HTML을 반환하지 않아야 합니다. 데모 SVG는 저장소에 직접 작성한 고정 자산으로 제한됩니다.
- `reportCount`는 0 이상의 안전한 정수입니다. 누락·잘못된 타입은 `null`로 처리하고 확인 불가로 표시합니다. `isReported`는 누군가의 신고 이력 유무이며 `reportedByUser`는 현재 사용자의 신고 완료입니다.
- `signals`의 각 항목은 `summary`, `source`, `evidenceIds[]`를 제공할 수 있습니다. UI에는 제공된 텍스트만 표시하며 HTML로 실행하지 않습니다.
- `evidence`의 각 항목은 `id`, `kind`, `source`, `summary`, `observedAt`을 제공합니다. 어댑터는 이 텍스트·유효한 시각 필드만 전달하고 임의의 `data` 객체를 UI로 전달하지 않습니다. `signals[].evidenceIds[]`와 `evidence[].id`를 연결해 관찰 근거를 표시합니다.
- `providers`의 각 항목은 `name`, `status`(`checked`, `failed`, `stale`), `matched`(`true`, `false`, `null`), `checkedAt`을 제공합니다. 조회 실패와 미확인을 미탐지로 해석하지 않습니다. 알 수 없는 제공자 상태는 실패로 표시합니다. `checkedAt`·`observedAt`이 누락되거나 유효하지 않으면 `null`이며 임의의 검사 시각을 만들지 않습니다.
- `scanId`는 1~128자의 영문자·숫자·밑줄·하이픈을 허용합니다. 신고에 필요하며 누락·잘못된 값이면 신고 성공을 가장하지 않습니다.

미리보기는 `src/services/preview-api.js`의 `loadPreviewImage()`를 통해 받아 Blob URL로 표시합니다. 이미지 요청도 `redirect: 'error'`로 리다이렉트를 따르지 않고 30초 제한·취소를 적용합니다. 실 API 응답은 Content-Type이 PNG·JPEG·WebP·GIF인 이미지에 한하며, 빈 이미지 또는 10MiB 초과 응답은 거부합니다. SVG는 데모 모드에서 고정된 두 로컬 데모 자산에 한해서만 허용합니다. 화면에서 사용이 끝난 Blob URL은 해제합니다.

## 작업 생성·폴링 방식

`scanTransport: 'job'`일 때 `POST /api/scans`에 동일한 `{ "url": "..." }` 본문을 보냅니다.

```json
{ "scanId": "scan-123", "status": "pending" }
```

이후 `GET /api/scans/scan-123`으로 상태를 조회합니다. 진행 응답은 동일한 `scanId`와 `pending` 또는 `running`을 반환해야 합니다. 백엔드가 실제로 화면 확인 단계에 도달했을 때만 `stage: "preview"`를 제공할 수 있습니다. 최종 조회 응답은 위의 완료 응답 형식입니다. 서버가 완료 데이터를 별도 `/report` 경로에서 제공한다면 서비스 계층을 해당 실제 계약에 맞게 수정합니다.

취소는 클라이언트의 요청·폴링을 중단합니다. 서버 작업 취소 API는 구현·가정하지 않으며 서버 검사도 취소됐다고 표시하지 않습니다.

## 신고 응답

`POST /api/scans/<scanId>/reports`

```json
{ "scanId": "scan-123" }
```

성공 응답:

```json
{ "reportCount": 129, "reportedByUser": true }
```

명시적 `reportedByUser: true` 응답 후에만 신고 완료로 표시합니다. 신고 건수는 서버 응답만 사용합니다. 서버의 중복 신고 정책·사용자 식별·집계·저장은 백엔드 범위이며 프런트에서 임의로 구현하지 않습니다.

신고 응답에서 `scanId`를 제공한다면 요청한 검사 ID와 일치해야 합니다. 다른 ID·잘못된 값은 신고 성공으로 표시하지 않습니다.

## 검증

정적 서버 실행 후 `/tests/frontend/services.html`에서 외부 의존성 없는 서비스 검증을 실행합니다. 테스트는 임시 fetch 대역으로 우리 API 요청·오류·신고 처리를 확인하고 실제 사이트에는 접속하지 않습니다. URL 검증, 개인정보 표시 제한, 정상 판정의 보수적 처리, 요청 일치, 스크린샷 출처 제한, 취소·제한 시간도 검사합니다.

브라우저 테스트 통과는 실제 백엔드·카메라·격리·신고 접수 검증을 뜻하지 않습니다. 실제 연동 시 Network 패널에서 목적지 접속이 정상 결과의 명시적 진입 클릭 전에는 발생하지 않는지 확인해야 합니다. Shadow DOM 내부 UI는 `shadowRoot` 순회 또는 이를 지원하는 검사 도구로 확인합니다.
