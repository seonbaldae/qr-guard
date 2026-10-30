# 프런트엔드 API 연결 안내

프런트엔드는 HTML·CSS·순수 JavaScript ES Modules와 open Shadow DOM을 사용합니다. 공개 배포와 로컬 Docker 개발의 API를 분리하며 Python의 중첩 보고서는 공통 `src/services/response-adapter.js`가 화면용 모델로 변환합니다. 두 구성 모두 기본은 실제 검사이며 API 오류를 데모 성공으로 대체하지 않습니다.

| 구성 | 요청 방식 | 검사 범위 | 미리보기·신고 |
| --- | --- | --- | --- |
| 공개 배포 | `POST /api/analyze`, 요청 안에서 완료 | URL 구조·Google Safe Browsing | 점검·준비 중, 실제 방문·집계 미제공 |
| 로컬 Docker | `POST /api/scans` + `GET /api/scans/{id}` | 정적 검사·격리 브라우저 관찰 | Worker PNG·단일 프로세스 신고 접수 |

## 공개 배포 API

Vercel의 `api/analyze.py`, `api/health.py`, `api/capabilities.py`가 `app/public_api.py`의 앱을 사용합니다. 같은 HTTPS 출처의 경로에 네이티브 Functions로 배포하며 rewrite나 별도 백엔드 URL이 필요하지 않습니다. 이 API는 수정 중인 Docker 코드와 로컬 작업 저장소를 가져오지 않습니다.

`POST /api/analyze`

```json
{"url":"https://example.com/","source":"manual"}
```

요청 안에서 위협 조회를 완료하고 중첩 보고서를 반환합니다. 클라이언트의 `mode` 값과 관계없이 공개 구성의 실제 범위는 `mode: "static"`, `analysisScope: "static"`입니다. 작업 ID는 응답 연결용이며 후속 폴링·PNG·신고 저장소가 있다는 뜻이 아닙니다.

| 공개 응답 정보 | 프런트 처리 |
| --- | --- |
| `mode: static`, `analysisScope: static` | 주소 검사 범위로 표시, 실제 방문 주소·이미지는 사용하지 않음 |
| `sandboxAnalysis.status: not_requested`, `skipReason: static_only` | 미리보기 점검 안내, 최종 목적지 미확인 |
| `previewAvailable: false` | 원본 사이트를 이미지나 HTML로 직접 요청하지 않음 |
| `reportAvailable: false` | 신고 버튼 비활성화, 준비 중 안내 |
| `reportCount: null`, `isReported: null` | 신고 수·이력 미확인, 0건으로 보정하지 않음 |
| Google 조회 성공·위협 미탐지 | “주소 검사에서 위협 미탐지”, 화면·최종 목적지를 확인하지 않았다는 안내 |
| Google 조회 실패·미확인 | 확인 불가, 사이트 진입 동작 없음 |

공개 주소 검사 결과도 제공자의 조회 상태와 명시적인 `verdict.level`을 사용합니다. URL 문자열의 안전성이나 공식 운영 주체를 인증하지 않습니다. 완료된 미탐지 결과의 진입 버튼은 표시된 **원본 주소**를 사용자 클릭으로만 엽니다. 알려진 위협 결과에는 접속 버튼을 제공하지 않습니다.

`GET /api/health`는 API 생존 상태와 아래 기능 정보를, `GET /api/capabilities`는 기능 정보만 반환합니다.

```json
{"scanTransport":"direct","scanMode":"static","analysisScope":"static","previewAvailable":false,"reportAvailable":false}
```

이 API는 인스턴스 간 메모리 상태 공유에 의존하지 않습니다. 현재 공유 신고 저장소가 없어 공개 신고 기능은 제공하지 않습니다. 로컬 메모리 신고 건수를 공개 통계로 사용하지 마세요. API 응답은 `no-store`, 요청 본문은 최대 16KiB, 위협 조회는 최대 12초이며 Vercel 함수 최대 실행시간은 30초입니다. 오류 응답은 입력 URL·키를 되돌려 보내지 않습니다.

공개 구성을 로컬에서 재현할 때는 서버 전용 Google 키를 준비하고 두 터미널에서 실행합니다.

```sh
# 터미널 1
.venv/bin/python -m uvicorn app.public_api:app --host 127.0.0.1 --port 8001 --no-access-log
```

```sh
# 터미널 2
node scripts/prepare-vercel.mjs --public
PORT=8086 QR_GUARD_API=http://127.0.0.1:8001 node scripts/dev-server.mjs --public
```

`http://127.0.0.1:8086/`을 엽니다. 이는 공개 배포 구성의 로컬 재현입니다. 실제 공개 URL의 배포 상태는 별도로 확인합니다.

## 로컬 Docker 실행

Docker Desktop과 저장소의 Python 가상 환경·Node.js가 준비된 상태에서 실행합니다.

```sh
.venv/bin/python scripts/run-local.py
```

이미지를 이미 빌드했다면 `--skip-build`를 사용할 수 있습니다. 기본 화면은 [로컬 QR Guard](http://127.0.0.1:8080/)입니다. 스크립트는 Docker Worker 설정을 확인하고 단일 FastAPI 프로세스와 프런트 서버를 시작합니다. 기본 모드의 실제 방문 대상은 Worker 안의 무해한 페이지 `http://127.0.0.1:4000/demo/normal`입니다. 이 주소를 직접 입력하면 사용자 브라우저가 해당 주소에 접속하지 않고 API→Worker를 통해 검사합니다. Google 조회도 실제 API를 사용하므로 서버 키가 필요합니다.

공개 웹 주소의 실제 미리보기는 다음처럼 별도 옵션을 켭니다.

```sh
.venv/bin/python scripts/run-local.py --skip-build --public-preview
```

첫 실행이나 이미지 변경 후에는 `--skip-build`를 빼고 실행합니다. 기존 Worker의 모드·이미지가 다르면 실행을 거부하며 자동 교체하지 않습니다. Ctrl+C로 서버와 실행기가 만든 컨테이너를 정리하고 기존 컨테이너는 보존합니다.

이 모드는 공개 HTTP 80·HTTPS 443의 IPv4 연결만 허용합니다. Worker의 네트워크는 `none`을 유지하고 loopback 프록시→표준 입출력 터널→호스트 TCP 중계기를 통합니다. 중계기는 DNS 반환 주소를 모두 검사하고 공인 IPv4 주소에 연결을 고정해 내부·메타데이터 접근을 차단합니다. HTTPS 인증서 검증은 Chromium이 그대로 수행합니다. 폼·비읽기 요청·WebSocket 등은 브라우저 정책으로 제한하며 HTTPS 내용을 중계기에서 복호화해 검사하지는 않습니다. 차단·관찰 제한은 결과에 반영됩니다. 자세한 구조와 한계는 [Worker 안내](../worker/README.md)를 참고하세요.

`--public-preview`에서도 앱과 API는 로컬에만 열립니다. Vercel 공개 프런트에서 이 로컬 API를 사용할 수 있게 되는 옵션은 아닙니다. 실제 `example.com`의 Google 조회·격리 PNG·최종 URL·정상 결과 UI를 로컬에서 확인했지만, 임의 악성 사이트 운영 안전성이나 신규 사칭 탐지를 보증하지 않습니다.

프런트와 API만 따로 실행하려면 다음을 사용합니다. 이 경우 Worker 설정은 자동으로 준비되지 않습니다.

```sh
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
node scripts/dev-server.mjs
```

`scripts/dev-server.mjs`는 정적 파일을 제공하고 `/api/*`를 `QR_GUARD_API`(기본 `http://127.0.0.1:8000`)로 전달합니다. 브라우저에는 같은 출처로 보이므로 이 구성에는 CORS 설정이 필요 없습니다. 이 개발 서버는 Vercel 정적 출력에 포함되지 않습니다.

## 로컬 작업 생성·조회

`POST /api/scans`

```json
{"url":"https://example.com/","source":"qr","mode":"sandbox"}
```

생성 응답은 HTTP 202입니다.

```json
{"scanId":"scan-123","status":"queued","mode":"sandbox"}
```

- QR 입력은 `source: "qr"`, 직접 입력은 `"manual"`이며 재검사에도 출처를 유지합니다. 서버 기본 모드는 `static`이지만 프런트는 `sandbox`를 명시합니다.
- `www.example.test/path`처럼 프로토콜 없는 웹 주소는 입력 단계에서 `https://`를 보완합니다. 명시한 `http://`는 유지합니다. API 응답·진입 주소에는 이 보완을 적용하지 않고 명시적인 HTTP(S) 주소만 허용합니다.
- URL이 아닌 QR은 촬영 화면에서 오류를 표시하며 수동 입력창으로 포커스를 옮기지 않습니다.
- `GET /api/scans/{scanId}`로 `queued`·`running` 동안 1.2초 간격으로 조회합니다. 전체 검사의 제한 시간은 60초입니다.
- 실제 `sandboxAnalysis.status: "running"`일 때만 격리 환경에서 화면을 확인 중이라는 안내를 표시합니다.
- 클라이언트 취소는 요청·폴링을 중단합니다. 서버 검사 취소 API는 없으며 서버 작업까지 중단됐다고 표시하지 않습니다.

백엔드 보고서의 주요 변환은 다음과 같습니다.

| 백엔드 | 화면 처리 |
| --- | --- |
| `status: queued` | `pending`, 계속 폴링 |
| `verdict.level`: `malicious` / `suspicious` / `no_known_threat` / `unknown` | `phishing` / `suspicious` / `clear` / `inconclusive` |
| `verdict: null` 또는 알 수 없는 판정 | 확인 불가 |
| sandbox 모드에서 격리 방문 미완료인 `no_known_threat` | 확인 불가로 낮춤 |
| `verdict.reasons`, `verdict.evidenceIds` | 판정 이유와 관찰 근거 연결 |
| `sandboxAnalysis.finalUrl` | 실제 도착 주소, 미확인 시 `null` |
| `staticAnalysis.signals` + `sandboxAnalysis.signals` | 확인한 내용 |
| `staticAnalysis.providers`, `evidence` | 출처·조회 상태·관찰 근거 |
| 세 분석 부분의 `limitations` | 중복을 제거한 검사 한계 |
| `sandboxAnalysis.errorCode` | 알려진 오류 범주만 한국어로 안내 |
| `reportCount`, `isReported`, `reportedByUser` | 실제 서버 신고 집계·이 검사에서의 접수 여부 |
| `analysisScope: static` | 주소 검사만 수행했음을 표시, 방문 주소·이미지 미사용 |
| `reportAvailable: false` | 신고 미제공 안내, UI·앱·서비스 계층에서 접수 차단 |
| `updatedAt` | 데이터의 검사 시각 유지 |

`requestedUrl`은 현재 요청과 정규화 후 일치해야 합니다. 다른 검사 ID·주소의 응답은 거부합니다. 정적 분석 완료나 빈 신호만으로 정상 판정을 만들지 않습니다. 실패한 검사, 조회 실패, 최종 URL 오류를 정상으로 보정하지 않습니다. 판정 이유와 근거는 `textContent`로 표시하며 외부 HTML을 실행하지 않습니다.

## 로컬 스크린샷

`sandboxAnalysis.screenshot.status`가 `ready`이고 `available: true`일 때만 `GET /api/scans/{scanId}/screenshot`을 요청합니다. 백엔드는 검증된 PNG 바이트를 반환합니다. 알려진 위협으로 미방문한 경우, 접근 정책에 의한 차단, 시간 초과·촬영 실패는 서로 다른 안내를 제공합니다.

프런트의 `loadPreviewImage()`는 설정된 API 출처의 허용된 이미지 경로만 요청합니다. 리다이렉트를 따르지 않고 60초 제한·취소를 적용합니다. 실제 API 이미지는 PNG·JPEG·WebP·GIF만 허용하며 빈 이미지와 10MiB 초과 응답을 거부합니다. 이미지 Blob URL은 화면 이탈 시 해제합니다. SVG는 저장소에 직접 작성한 두 개의 고정 데모 자산에만 허용합니다.

사용자 기기는 검사 대상의 HTML·JS·favicon·iframe을 로드하지 않습니다. 완료된 정상 판정에서 사용자가 **사이트 들어가기**를 누를 때만 관찰된 최종 URL을 엽니다. 최종 URL이 없는 정상 완료 응답은 원래 주소와 최종 목적지 미확인 안내를 사용합니다. 피싱·의심·확인 불가 결과에는 목적지 접속 동작을 제공하지 않습니다.

## 로컬 신고

완료된 `malicious` 검사 결과에서만 명시적으로 신고를 요청합니다.

`POST /api/scans/{scanId}/reports`

```json
{"scanId":"scan-123"}
```

접수 응답과 이후 검사 조회에는 다음 필드가 포함됩니다.

```json
{"scanId":"scan-123","reportCount":1,"isReported":true,"reportedByUser":true}
```

이는 외부 기관에 보내는 신고가 아닙니다. `reportCount`는 **현재 서버 프로세스가 동일한 정규화 URL에 접수한 횟수**입니다. `reportedByUser`는 인증된 사용자 신원이 아니라 **해당 검사 ID에서 접수했는지**를 뜻합니다. 같은 검사 ID의 재요청은 건수를 늘리지 않으며 새 검사 ID는 별도로 접수할 수 있습니다. 재시작하면 집계와 접수 이력이 사라집니다. 운영용 사용자 중복 방지·영구 저장은 구현하지 않았습니다.

프런트는 서버의 `reportedByUser: true`를 확인한 뒤에만 신고 완료로 바꾸고 서버 건수만 사용합니다. 미제공·잘못된 건수는 `0`으로 만들지 않고 확인 불가로 표시합니다. 실패하면 기존 판정·건수를 유지하고 재시도를 제공합니다. 단순 `isReported: true`만으로 현재 검사의 신고 버튼을 막지 않습니다.

## 설정·개인정보·배포

`src/config.js`는 같은 출처(`apiBaseUrl: ''`), 전체 제한 60초, 로컬 작업 폴링 1.2초를 사용합니다. `src/deployment-config.js`의 소스 기본값은 `job/sandbox`입니다. `node scripts/prepare-vercel.mjs --public`은 정적 파일을 복사한 뒤 생성된 `dist/src/deployment-config.js`만 `direct/static`으로 기록합니다. 소스의 로컬 설정은 바꾸지 않습니다. 두 구성의 실제 경로는 각각 `app/main.py`와 `app/public_api.py`를 기준으로 확인합니다.

별도 API 출처를 설정한다면 정확한 HTTPS 출처와 서버 CORS 설정을 함께 준비해야 합니다. Google 키는 백엔드 설정에만 넣습니다. 프런트는 검사 시작 전에 검사 URL이 Google에 전송된다는 안내를 표시합니다. 카메라 영상·QR 이미지는 업로드하지 않으며 URL·결과·신고 상태를 브라우저 저장소에 기록하지 않습니다.

Vercel 배포 구성은 `dist/` 프런트와 별도로 빌드한 Python Functions를 같은 출처에 제공합니다. `.vercelignore`는 공개 API의 소스 의존성만 허용하며 Worker·로컬 작업 서버·테스트·비밀 파일은 제외합니다. Google 키는 Vercel 서버 환경 변수로만 설정하며 정적 파일에 포함하지 않습니다. 코드·로컬 검사 완료와 실제 공개 배포 완료를 구분해 보고합니다.

## 데모와 검증

프런트만 보려면 `python3 -m http.server 8080 --bind 127.0.0.1`로 실행할 수 있습니다. 이 서버에는 API가 없으며 실제 검사는 연결 오류가 됩니다. “샘플로 확인하기”는 명시적인 fixture 모드이며 실제 방문·판정·신고를 수행하지 않습니다. API 오류를 데모 성공으로 바꾸지 않습니다.

`/tests/frontend/services.html`과 `/tests/frontend/ui.html`은 소스를 제공하는 정적 서버에서 실행하는 브라우저 기본 기능 테스트입니다. 공개 `dist/`에는 테스트를 포함하지 않습니다. API와 새 창은 대역으로 처리하며 실제 외부 사이트에 접속하지 않습니다. 서비스 43개와 UI 17개가 현재 회귀 검사 범위입니다. 공개 API의 서버리스 무상태 처리와 입력·오류 경계는 Python 회귀 검사에서 확인합니다.

실제 하드웨어 카메라 촬영과 모든 휴대전화의 QR 호환성은 별도 검증이 필요합니다. HTTPS는 카메라 권한의 보안 컨텍스트를 제공하지만 브라우저의 `BarcodeDetector` 지원을 추가하지 않습니다. QR 지원·권한을 확인하며 미지원 환경에는 직접 입력 대안을 제공합니다. Shadow DOM 내부는 `shadowRoot`를 순회하는 도구로 확인합니다.
