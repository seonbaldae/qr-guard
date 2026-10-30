# QR Guard

QR에 담긴 주소를 바로 열지 않고 먼저 검사하는 해커톤용 QR 피싱 예방 서비스입니다.
저장소에는 모바일 프런트엔드와 기존 `app/precheck/` 정적 분석을 공개 API에 연결한 FastAPI 서버가 있습니다.
**프런트와 백엔드의 실제 연동, Docker/Playwright Worker 및 네트워크 격리 검증은 아직 완료되지 않았습니다.**

## 구성과 현재 상태

- **프런트엔드:** QR 촬영 → 검사 중 → 결과 확인의 세 화면을 HTML, CSS, 순수 JavaScript ES Modules와 open Shadow DOM으로 구현했습니다. 프런트 실행에는 패키지 설치나 빌드가 필요하지 않습니다.
- **모바일 화면:** 한 열 구조로, 상단 헤더·단계 표시·서비스 소개를 생략하고 흰색·파란색·회색과 큰 버튼으로 촬영과 결과에 집중합니다. 주소 직접 입력과 샘플 체험은 촬영 화면에서 펼쳐 사용할 수 있습니다.
- **백엔드:** 검사 작업 생성·조회·PNG 조회 API와 정적 분석·Google Safe Browsing v5 조회, 내부 Worker HTTP 어댑터를 제공합니다. 해커톤용 단일 프로세스 메모리 서버입니다.
- **Worker:** 실제 Docker/Playwright 서비스는 이 저장소에 포함되지 않습니다. 미연결 상태에서는 sandbox 검사가 `blocked`이며, 알려진 위협 등 별도 판정 근거가 없으면 최종 판정은 `unknown`입니다.
- **신고:** 프런트 UI와 명시적인 모의 신고는 있습니다. 실제 신고 접수·집계 API는 현재 백엔드에 없습니다.

## 프런트엔드 실행과 화면 체험

저장소 루트에서 정적 서버를 실행합니다.

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

[로컬 화면](http://127.0.0.1:8080/)을 엽니다. QR 촬영은 브라우저의 기본 `BarcodeDetector`가 `qr_code`를 지원해야 합니다. 미지원 환경에서는 URL 직접 입력을 이용할 수 있습니다. 휴대전화 카메라는 HTTPS 환경이 필요하며, 일반 HTTP LAN 주소로는 사용할 수 없습니다.

- **실제 검사 모드:** 읽은 URL을 설정된 우리 검사 API에만 전달합니다. 정상 완료 결과에만 사이트 진입 버튼을 제공하고, 피싱 결과에는 신고 건수와 신고·재스캔 버튼을 제공합니다. 현재는 아래의 API 계약 차이를 먼저 해소해야 실제 서버와 연결할 수 있습니다.
- **샘플 체험:** 촬영 화면의 “샘플로 확인하기”에서 정상·피싱 결과를 선택합니다. 사칭 의심, 확인 불가, 검사 오류, 미리보기 없음, 신고 실패도 체험할 수 있습니다. 데모 화면에는 실제 검사가 아니라는 안내를 표시하며 실제 사이트 이동은 비활성화합니다.

정적 서버는 API 요청을 처리하거나 FastAPI로 전달하지 않습니다. 기본 프런트 설정에서 직접 주소를 검사하면 API 연결 오류가 표시되며, 이를 데모 성공으로 자동 대체하지 않습니다.

## GitHub → Vercel 프런트 배포

모의 피싱 사이트와 같은 GitHub 연동 방식으로 **모바일 프런트엔드**를 Vercel에 배포할 수 있습니다. 저장소 루트의 `vercel.json`이 정적 사이트 설정을 지정합니다. 프로젝트의 프레임워크는 **Other**로 사용하며 Python/FastAPI 자동 감지를 사용하지 않습니다.

1. [Vercel 새 프로젝트](https://vercel.com/new)에서 GitHub 저장소 `seonbaldae/qr-guard`를 가져옵니다. 목록에 없다면 Vercel GitHub App에 해당 저장소 접근을 허용합니다.
2. **Root Directory**를 저장소 루트(`./`), **Framework Preset**을 **Other**로 선택합니다.
3. 아래 설정이 적용되는지 확인한 뒤 배포합니다. 기존 Vercel 프로젝트가 있다면 새로 만들지 말고 해당 프로젝트의 Git 저장소와 설정을 확인합니다.

| 설정 | 값 |
| --- | --- |
| Framework Preset | `Other` (`framework: null`) |
| Install Command | 실행하지 않음 (`installCommand: ""`) |
| Build Command | `node scripts/prepare-vercel.mjs` |
| Output Directory | `dist` |
| 환경 변수 | 프런트 화면·샘플 체험에는 필요 없음 |

이 단계는 Node.js 기본 기능으로 정적 파일을 복사하는 작업입니다. npm 의존성·패키지 설정·번들러·트랜스파일러를 추가하지 않습니다. Vercel 빌드 환경의 Node.js를 사용하며 로컬 프런트 개발에는 여전히 빌드가 필요하지 않습니다.

`scripts/prepare-vercel.mjs`는 기존 `dist/`를 새로 만들고 `index.html`, `src/`의 JS·CSS, `assets/`의 이미지 파일만 복사합니다. ES Modules와 `/assets/...` 경로는 그대로 유지합니다. **출력 디렉토리를 저장소 루트 `.`로 바꾸지 마세요.** 이 저장소에는 백엔드·문서·테스트도 있기 때문에 공개 파일을 `dist/`로 제한합니다.

`.vercelignore`는 CLI 업로드를 프런트 파일과 복사 스크립트로 제한합니다. Git 연동 배포의 공개 범위는 `dist/`에 복사한 파일 목록으로 제한합니다. `.vercel/` 연결 정보와 생성된 `dist/`는 `.gitignore`에 포함됩니다.

GitHub와 Vercel은 최초 한 번 연결해야 합니다. 설정 파일을 푸시하는 것만으로 계정 연결이 생성되지는 않습니다. 연결 후 Production Branch(보통 `main`)에 푸시하면 Production 배포가 갱신되고, 다른 브랜치·PR에는 Preview 배포가 생성됩니다. 별도 GitHub Actions나 `VERCEL_TOKEN`은 필요하지 않습니다. 설정 근거: [Vercel 정적 설정](https://vercel.com/docs/project-configuration/vercel-json), [GitHub 연동 배포](https://vercel.com/docs/git/vercel-for-github), [CLI 업로드 제외](https://vercel.com/docs/deployments/vercel-ignore).

Vercel의 HTTPS 배포 주소에서 카메라를 사용할 수 있지만, 브라우저의 QR 인식 API 지원과 카메라 권한은 여전히 필요합니다. 배포 후 촬영 화면·“샘플로 확인하기”의 정상/피싱 결과·미리보기 이미지·재스캔을 확인하세요.

로컬에서 실제 정적 배포 출력만 확인하려면 다음과 같이 실행합니다.

```sh
node scripts/prepare-vercel.mjs
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

Vercel에는 FastAPI·Worker·신고 API가 함께 배포되지 않습니다. 현재 FastAPI는 단일 프로세스의 메모리에 검사 작업과 PNG를 보관하므로 기존 별도 서버 실행 방식을 유지합니다. 실제 검사는 아래의 프런트 API 계약 조정과 별도 HTTPS 백엔드 연결이 필요합니다. 프런트의 `apiBaseUrl`과 백엔드 CORS 출처를 실제 배포 주소에 맞춰야 하며, Google API 키는 백엔드에만 설정합니다. 그 전까지는 샘플 체험을 사용할 수 있고 실제 검사 요청은 연결 오류로 처리됩니다.

## 백엔드 실행

Python 3.11 이상이 필요합니다. 저장소 루트에서 개발·테스트 의존성을 설치하고 실행합니다.

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

[Swagger](http://127.0.0.1:8000/docs)와 [OpenAPI](http://127.0.0.1:8000/openapi.json)에서 실제 API 계약을 확인할 수 있습니다. 실행용 의존성만 설치하려면 `requirements.txt`를 사용합니다.

메모리 저장소이므로 반드시 **프로세스 1개**로 실행합니다. 재시작하면 검사 결과와 PNG가 사라집니다.
인증·영구 보관·운영 환경 배포 설정은 제공하지 않으므로 공개 인터넷에 그대로 노출하지 마세요.

## 실제 API 계약과 프런트 연동 과제

현재 백엔드가 제공하는 요청은 다음과 같습니다.

| 요청 | 결과 |
| --- | --- |
| `POST /api/scans` | 202 `{scanId,status:"queued",mode}` |
| `GET /api/scans/{scanId}` | 200 camelCase `ScanReport`, 없는 ID는 404 |
| `GET /api/scans/{scanId}/screenshot` | 준비된 경우 200 `image/png`, 미준비·실패는 409, 없는 ID는 404 |
| `GET /api/health` | 프로세스 생존 확인만 수행 |

생성 요청 예시:

```json
{"url":"https://example.com/","source":"qr","mode":"sandbox","expectedBrand":"naver"}
```

- `source` 기본값은 `qr`, `mode` 기본값은 `static`입니다. **격리 미리보기를 요청하는 QR UI는 `sandbox`를 명시해야 합니다.**
- `expectedBrand`는 선택 값이며 현재 검증된 브랜드 ID는 `naver`입니다. 모르는 ID를 추측하지 않습니다.
- `status`가 `completed` 또는 `failed`일 때까지 결과를 조회합니다. `completed`와 안전 판정은 다릅니다.
- 화면은 `verdict.level`의 `malicious`, `suspicious`, `no_known_threat`, `unknown`을 구분해야 합니다.
- 최종 주소는 `sandboxAnalysis.finalUrl`입니다. 스크린샷은 `sandboxAnalysis.screenshot.available=true`일 때만 해당 검사 ID의 이미지 API로 요청합니다. 반환된 HTML/JS를 실행하지 않습니다.
- 취소 API·WebSocket·자동 목적지 열기는 구현하지 않습니다. 클라이언트 요청 취소를 서버 작업 취소로 설명하지 않습니다.

프런트 연동 설정은 `src/config.js`, 요청 처리는 `src/services/scan-api.js`, 응답 변환은 `src/services/response-adapter.js`에 있습니다. 현재 프런트는 먼저 작성한 제안 계약을 사용하므로 **서버를 실행하거나 설정만 변경하는 것으로 연동이 완료되지는 않습니다.**

| 항목 | 현재 프런트 | 현재 백엔드 / 필요한 조정 |
| --- | --- | --- |
| 검사 요청 | 기본 `POST /api/analyze`, 본문 `{url}` | `POST /api/scans`에 `source`, `mode` 등을 전달하도록 조정 |
| 작업 조회 | `pending`, `running`에서 폴링 | 생성 응답의 `queued`도 처리해야 함 |
| 판정 | `clear`, `phishing`, `suspicious`, `inconclusive` 문자열 | `verdict.level` 객체를 화면용 판정으로 변환해야 함 |
| 결과 필드 | 최상위 `finalUrl`, `screenshotUrl`, `signals`, `providers`, `limitations` | `staticAnalysis`, `sandboxAnalysis`, `verdict`, `evidence`를 화면용 모델로 변환해야 함 |
| 신고 | `POST /api/scans/{scanId}/reports`와 신고 건수 응답을 기대 | 현재 미구현. 실제 접수·건수를 표시하려면 별도 연동 필요 |

[프런트 API 안내](docs/frontend-api.md)는 현재 프런트가 기대하는 **제안 계약**을 설명합니다. 실제 서버의 제공 여부는 위 API 목록과 OpenAPI를 기준으로 확인하세요.

프런트 8080과 백엔드 8000을 별도로 실행하면 프런트의 `apiBaseUrl`과 백엔드 CORS 출처를 맞춰야 합니다. 백엔드는 기본적으로 타 출처를 허용하지 않습니다. 예를 들어 프런트 주소가 `http://127.0.0.1:8080`이면 다음 값을 서버 실행 환경에 설정합니다.

```sh
export QR_GUARD_CORS_ORIGINS=http://127.0.0.1:8080
```

여러 origin은 쉼표로 구분합니다. `localhost`와 `127.0.0.1`은 다른 origin이며 `*`와 쿠키 인증은 사용하지 않습니다. CORS 설정은 위 요청·응답 계약 조정을 대신하지 않습니다.

## 정적 분석 / Google Safe Browsing v5

정적 위협 조회는 Google Safe Browsing v5 단독입니다. `app/static_adapter.py`가 `app/precheck/`의 `analyze(url, check)` 결과를 공개 응답으로 변환하며, Google의 providers·signals·evidence를 보존하고 OpenPhish로 덮어쓰지 않습니다.

서버에서 `GOOGLE_SAFE_BROWSING_API_KEY`를 설정하세요. 키를 프런트·URL·로그·Git에 넣지 마세요.
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

**개인정보·이용 조건:** 쿼리 등을 포함한 검사 URL이 Google에 전송됩니다. 실제 연동 전에 프런트에 전송 고지를 반영해야 합니다.
실제 인증 토큰·개인정보가 포함된 URL은 시연에 사용하지 마세요. API 응답 근거에는 URL·키 원문을 기록하지 않습니다.
Safe Browsing은 비상업적 사용 조건과 경고·출처 표시 요구사항을 검토해야 하며,
미탐지는 Google 또는 우리 서비스의 안전 보장이 아닙니다.
참고: [Google Safe Browsing v5 URL 검색](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search)

## C Worker 연결

`app/worker.py`는 실제 내부 HTTP 호출 어댑터이며 Worker 서비스 자체가 아닙니다. 다음 설정을 모두 충족하기 전에는 호출하지 않습니다.

| 환경 변수 | 설명 |
| --- | --- |
| `QR_GUARD_WORKER_URL` | 신뢰하는 내부 Worker origin. 예: `http://worker:8001` |
| `QR_GUARD_DEMO_ORIGINS` | 별도로 통제하는 데모 사이트의 정확한 origin 목록 |
| `QR_GUARD_WORKER_EGRESS_VERIFIED` | 실제 네트워크 격리 검증 후에만 `true` |
| `QR_GUARD_MAX_SCANS` | 메모리 보관 상한. 기본 100건, 초과 생성은 503 |
| `QR_GUARD_WORKER_CONCURRENCY` | 동시 Worker 호출 상한. 기본 2건 |

어댑터는 `POST /internal/analyze`로 `{scanId,url,timeoutMs}`를 전달합니다.
반환되는 `finalUrl/httpStatus/pageTitle/passwordFieldCount/sensitiveFieldTypes/forms/requestHosts/redirected/screenshotBase64/limitations`
형태는 Worker 어댑터 계약을 따릅니다. 기본 timeout은 20초이고, HTTP redirect를 따라가지 않으며 환경 프록시를 상속하지 않습니다.
응답은 6 MiB, PNG는 4 MiB·1600만 픽셀 이내로 제한하고 PNG 형식을 검증합니다.
PNG는 청크 검사뿐 아니라 실제 픽셀 디코딩도 수행합니다. Worker가 보고한 CAPTCHA·DOM 관찰 제한은
URL·토큰 원문 없이 제한된 사유 범주로 전달합니다. 보관 상한 도달 시 자동 삭제하지 않으므로 데모를 재시작해야 합니다.

**이 origin 검사는 네트워크 방화벽이 아닙니다.** C Worker가 redirect·DNS rebinding·하위 리소스까지 실제 네트워크 egress를 제한하는지 확인해야 합니다.
플래그만 켜는 것으로 격리가 구현되지 않습니다. 임의 악성 사이트를 방문하거나 실제 인증정보 입력·폼 제출을 수행하지 마세요.

판정 우선순위는 Google의 알려진 위협 탐지 → 브랜드 불일치와 관찰된 비밀번호 필드 조합 → 필요 검사 완료 시 범위 내 미탐지 → 그 외 확인 불가입니다.
요청 URL의 위협이 확인되면 Worker는 호출하지 않습니다. Worker 완료 후 최종 도착 URL도 Google에 확인하며,
위협이 발견돼도 실제 완료된 sandbox와 스크린샷 상태는 유지합니다.
네이버 도메인 매핑 출처: [네이버 공식 포털 서비스 소개](https://www.navercorp.com/service/portal)의 `https://www.naver.com/` 링크.

## 검증

프런트 정적 서버에서 다음 페이지를 열면 외부 의존성 없이 검증을 실행합니다.

- [서비스 계층 검증](http://127.0.0.1:8080/tests/frontend/services.html): URL·응답 검증, API 오류·취소·제한 시간, 이미지 출처와 신고 처리.
- [화면 통합 검증](http://127.0.0.1:8080/tests/frontend/ui.html): 실제 Shadow DOM의 폼·버튼, 정상·피싱 분기, 신고 성공·실패, 이전 응답 무시, 재스캔 초기화. API와 새 창은 테스트 대역으로 처리합니다.

백엔드 테스트는 개발 의존성 설치 후 실행합니다.

```sh
.venv/bin/python -m pytest -q
```

기존 정적 분석 테스트 외에 공개 API·판정 분기·오류 처리·CORS·allowlist·PNG·캐시 검사 테스트가 있습니다.
API 테스트의 Google·Worker 응답은 **명시적인 테스트 데이터**이며 실제 외부 Google 조회 성공을 의미하지 않습니다.
실제 Uvicorn HTTP 생성·조회·입력 오류·미연결 Worker 차단을 확인하는 테스트도 포함되어 있습니다.

## 검증 범위와 남은 작업

- 실제 프런트 연동에는 요청·응답 어댑터, `sandbox` 모드, 주소/CORS 설정, Google 전송 고지, 신고 API 연결이 필요합니다.
- 실제 C Worker와 프런트가 연결되면 **D1: Shadow DOM 비밀번호 관찰 → 브랜드 불일치 근거 → suspicious → 실제 PNG 조회**를 E2E로 검증해야 합니다.
- 실제 카메라 QR 판독, C Worker 실브라우저 D1, 네트워크 격리, 프런트부터 실제 신고 접수까지의 통합 검증은 완료하지 않았습니다. 모의 테스트 통과를 이 검증의 완료로 해석하지 않습니다.
- 위협 미탐지는 완전한 안전이나 공식 사이트 인증을 뜻하지 않습니다. QR 목적지는 정상 결과의 명시적 진입 클릭 전까지 사용자 기기에서 열지 않습니다.
- 프런트엔드는 카메라 영상·검사 데이터를 브라우저 저장소에 기록하지 않습니다. Shadow DOM 내부를 검사하려면 `shadowRoot` 순회 또는 이를 지원하는 도구를 사용하세요.
