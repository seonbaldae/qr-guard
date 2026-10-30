# QR Guard

QR에 담긴 주소를 사용자 기기에서 바로 열지 않고 먼저 검사하는 해커톤 서비스입니다. 공개 배포용 주소 검사와 로컬 Docker 미리보기를 분리했습니다.

## 구현된 흐름

- **모바일 프런트:** HTML·CSS·순수 JavaScript ES Modules, Web Components와 open Shadow DOM으로 QR 촬영 → 검사 중 → 결과의 세 화면을 제공합니다. QR 인식은 브라우저의 `BarcodeDetector`를 사용하며 직접 입력도 지원합니다. 프로토콜 없는 웹 주소에는 입력 단계에서만 `https://`를 보완합니다.
- **공개 API 구성:** `app/public_api.py`가 한 요청 안에서 정적 검사를 완료합니다. Vercel의 `POST /api/analyze`와 같은 출처로 연결하며 Docker나 메모리 작업 폴링에 의존하지 않습니다. 미리보기와 신고는 준비 중으로 표시합니다.
- **로컬 통합 API:** `app/main.py`는 기존 작업 생성·조회·PNG 조회·신고 접수를 처리합니다. 로컬 프런트는 작업 완료를 폴링합니다. 프런트 전체 검사 제한은 두 구성 모두 60초입니다.
- **정적 검사:** URL 구조와 Google Safe Browsing v5를 확인합니다. Google 조회 실패를 미탐지로 바꾸지 않으며 키는 서버에서만 사용합니다. 검사 시작 전 URL이 Google에 전송된다는 안내를 제공합니다.
- **Docker Worker:** Playwright·Chromium이 별도 컨테이너에서 페이지를 방문하고 실제 PNG·최종 URL·DOM 및 네트워크 관찰을 반환합니다. 로컬 통합 실행은 `--network none`을 유지하고 호스트 API가 제한된 `docker exec` 전송으로 Worker 작업을 생성·조회합니다.
- **로컬 신고:** 완료된 악성 판정에 대한 신고를 현재 로컬 서버 프로세스에서 접수합니다. 같은 검사 ID의 중복 요청은 한 번만 집계합니다. 공개 배포에는 공유 저장소가 없으므로 이 메모리 집계를 사용하지 않습니다.

정상 완료 결과에만 사용자가 직접 누를 수 있는 **사이트 들어가기** 버튼을 제공합니다. 피싱·의심·확인 불가 결과에는 접속 동작을 제공하지 않습니다. 알려진 위협이 발견되면 Worker 방문을 생략합니다. 미탐지는 완전한 안전이나 공식 사이트 인증을 뜻하지 않습니다.

## 다른 휴대전화에서 사용할 공개 서비스

[QR Guard 열기](https://qr-guard-five.vercel.app/). 2026-10-31에 프런트와 정적 검사 API의 Vercel Production 배포를 완료했습니다. 로그인 쿠키 없이 공개 `GET /api/health`와 `POST /api/analyze`의 실제 Google 조회를 확인했습니다. 현재 공개 서비스는 **주소 검사**를 제공하며 Docker 미리보기와 신고는 준비 중입니다.

실제 공개 주소에서 `example.com`은 조회 완료·위협 미탐지, Google 공식 피싱 테스트 주소는 알려진 위협으로 반환됐습니다. 두 결과 모두 실제 방문을 수행하지 않아 최종 URL은 `null`, 미리보기·신고 제공 여부는 `false`, 신고 건수는 미확인입니다. 배포 및 공개 HTTP 검증의 상세 범위는 [공개 배포 검증](docs/public-deployment.md)에 기록합니다.

| 구분 | 공개 Vercel 구성 | 로컬 Docker 통합 구성 |
| --- | --- | --- |
| 검사 요청 | `POST /api/analyze`, 요청 안에서 완료 | `POST /api/scans`, 상태 폴링 |
| 검사 범위 | URL 구조·Google Safe Browsing | 정적 검사·격리 방문·DOM·네트워크 관찰 |
| 실제 방문·이미지 | 방문하지 않음, 미리보기 점검 안내 | Worker가 확인한 경우에만 제공 |
| 최종 URL | `null`, 최종 목적지 미확인 | 실제 방문으로 관찰한 주소 |
| 신고 | 미제공, 건수 미확인·버튼 비활성화 | 단일 프로세스 메모리에 접수 |

공개 화면은 검사 전에 **“지금은 주소만 검사해요. 사이트 화면은 확인하지 않아요.”**를 안내합니다. Google 목록에 없는 주소도 화면·동작을 검사하지 않았으므로 최종 `unknown`으로 판단을 보류하며 사이트 진입을 제공하지 않습니다. 제공자의 목록 미일치 사실은 보존합니다. 알려진 위협은 위험 경고로 표시하고, 확인하지 않은 최종 목적지나 스크린샷을 만들지 않습니다. `reportAvailable: false`이면 신고 건수는 `null`로 유지하고 “신고 기능 준비 중”을 표시합니다. 이 정책은 목록에 없는 사칭 사이트를 탐지한 것과는 구분합니다.

수정 중인 `worker/`와 로컬 Docker 실행 코드는 공개 API의 배포 소스에 포함하지 않습니다. 공개 API는 작업 ID를 서버리스 메모리에서 재조회하지 않아 인스턴스가 바뀌는 폴링 문제를 피합니다. Docker 미리보기와 신고를 공개 서비스에 추가하려면 별도 Worker의 격리·접근 제어와 공유 저장소를 검증한 뒤 계약과 배포 설정을 연결해야 합니다. 이 정적 검사 구성이 해당 기능까지 제공한다고 설명하지 마세요.

휴대전화에서는 HTTPS 주소로 접속해야 카메라 권한을 사용할 수 있습니다. HTTPS만으로 모든 브라우저의 QR 해독 지원이 생기지는 않습니다. `BarcodeDetector`의 QR 지원 여부를 확인하며 미지원 환경에는 주소 직접 입력을 제공합니다. 실제 하드웨어 카메라 촬영은 별도 검증 대상입니다.

## 로컬 통합 실행

Python 3.11 이상, Node.js, 실행 중인 Docker Desktop이 필요합니다. Python 환경이 없다면 다음과 같이 준비합니다.

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
```

서버 전용 환경 변수 `GOOGLE_SAFE_BROWSING_API_KEY`를 설정하거나 Git에서 제외된 저장소 루트 `.env`에 같은 이름으로 보관합니다. 실제 키를 소스·문서·프런트 설정·로그에 넣지 않습니다. 기본 조회 구현은 호환용 `SAFE_BROWSING_API_KEY`도 지원하지만 새 설정에는 정식 이름을 사용합니다.

```sh
.venv/bin/python scripts/run-local.py
```

이미 빌드한 이미지를 그대로 사용하려면 다음과 같이 실행합니다.

```sh
.venv/bin/python scripts/run-local.py --skip-build
```

[로컬 화면](http://127.0.0.1:8080/)과 [API 문서](http://127.0.0.1:8000/docs)를 엽니다. 포트가 사용 중이면 `--port`와 `--api-port`로 서로 다른 포트를 지정합니다. 기본 모드의 방문 허용 대상은 Worker가 직접 제공하는 무해한 페이지 **`http://127.0.0.1:4000/demo/normal`**입니다. 이 주소를 화면에 입력하면 실제 Google 조회 → Worker 방문 → PNG 검증 → 프런트 이미지 표시를 확인할 수 있습니다. 사용자 브라우저에서 대상 페이지를 미리 열지 않습니다.

실행기는 Worker의 네트워크·사용자·리소스·마운트·보안 설정을 검사한 뒤 API와 프런트 서버를 시작합니다. 프로세스는 loopback에만 바인딩됩니다. Ctrl+C로 종료하면 서버를 정리하며 실행기가 새로 만든 Worker도 제거합니다. 이미 존재하던 Worker는 보존하고 설정·이미지가 맞지 않으면 실행을 거부합니다. 실행한 작업·스크린샷·신고는 단일 API 프로세스 메모리에 있으므로 재시작하면 사라집니다.

### 공개 웹 주소의 로컬 미리보기

공개 HTTP(S) 사이트를 실제로 방문하려면 명시적으로 다음 옵션을 사용합니다.

```sh
.venv/bin/python scripts/run-local.py --skip-build --public-preview
```

처음 실행하거나 Worker 이미지가 바뀌었다면 `--skip-build`를 빼고 실행해 이미지를 준비합니다. 기존 컨테이너의 모드나 이미지가 요청과 다르면 자동 교체하지 않고 실패합니다. 기본 모드에서는 통제된 테스트 주소만 허용하며 이 옵션에서만 공개 주소 방문을 허용합니다. 프런트·API는 여전히 로컬 8080·8000 포트를 사용합니다. **이 옵션은 서버나 Worker를 인터넷에 공개하는 배포 기능이 아닙니다.**

Worker는 계속 `--network none`으로 실행합니다. 컨테이너 내부 loopback 프록시가 `docker exec`의 표준 입출력 터널을 통해 호스트의 제한된 TCP 중계기에 연결합니다. 중계기는 DNS의 반환 주소를 검사하고 허용된 숫자 IPv4 주소로 연결을 고정합니다. 사설망·loopback·링크 로컬·메타데이터 등 내부/특수 주소를 차단하며 공개 HTTP 80·HTTPS 443만 지원합니다. IPv6 전용 대상과 다른 포트는 지원하지 않습니다. 리다이렉트와 하위 리소스도 같은 중계 경로를 거칩니다.

HTTPS는 Chromium과 대상 서버 사이에서 인증서를 검증하며 중계기가 복호화하지 않습니다. 브라우저 라우팅은 GET·HEAD만 허용하고 폼 전송·WebSocket·서비스 워커·다운로드를 제한합니다. 다만 HTTPS 내부의 메서드 제한은 브라우저 정책에 의존하므로 브라우저 침해까지 견디는 독립적인 HTTP 방화벽으로 설명하지 않습니다. 차단된 리소스나 관찰 실패가 있으면 검사 범위가 불완전한 것으로 처리할 수 있습니다. Docker와 이 중계기는 VM 수준의 격리나 모든 신규 피싱의 탐지를 보증하지 않습니다.

로컬에서 `https://example.com/`의 실제 Google 조회, 최종 URL, PNG와 정상 결과 화면을 확인했습니다. 컨테이너의 직접 메타데이터 접근 차단도 확인했습니다. 이 검증은 임의 악성 페이지에 대한 운영 안전성 검증을 대신하지 않습니다.

## 프런트만 실행

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

이 정적 서버는 API를 처리하지 않습니다. 화면의 **샘플로 확인하기**는 명시적인 fixture 모드이며 실제 사이트 검사·방문·신고를 수행하지 않습니다. API 실패가 데모 성공으로 자동 대체되지 않습니다.

카메라는 QR 형식의 `BarcodeDetector` 지원, 권한, 보안 컨텍스트가 필요합니다. 미지원 환경에서는 직접 입력을 사용합니다. 휴대전화의 일반 HTTP LAN 주소에서는 카메라가 동작한다고 가정하지 마세요. 실제 휴대전화 QR 촬영은 별도 HTTPS 환경에서 검증해야 합니다.

## 로컬 통합 API

| 요청 | 결과 |
| --- | --- |
| `POST /api/scans` | 202 `{scanId,status:"queued",mode}` |
| `GET /api/scans/{scanId}` | 중첩 분석 보고서·최종 판정·현재 신고 정보, 없는 ID는 404 |
| `GET /api/scans/{scanId}/screenshot` | 준비된 PNG, 미준비는 409, 없는 ID는 404 |
| `POST /api/scans/{scanId}/reports` | 현재 검사에 대한 신고 접수·실제 집계 응답 |
| `GET /api/health` | API 프로세스 생존 확인 |

생성 요청 예시:

```json
{"url":"https://example.com/","source":"manual","mode":"sandbox"}
```

서버 기본 모드는 `static`이며 프런트는 `sandbox`를 명시합니다. 선택적인 `expectedBrand`의 검증된 ID는 현재 `naver`입니다. 프런트가 브랜드를 추측해서 넣지는 않습니다.

`verdict.level`은 `malicious`, `suspicious`, `no_known_threat`, `unknown`입니다. `completed`는 작업 완료이며 안전 판정을 뜻하지 않습니다. 프런트는 판정 이유·근거 ID, 정적/격리 신호, 조회 제공자, 검사 한계를 보존합니다. 실제 최종 URL은 `sandboxAnalysis.finalUrl`, 이미지 준비 여부는 `sandboxAnalysis.screenshot`으로 확인합니다. 현재 서버 취소 API는 없으며 화면의 취소는 클라이언트 요청·폴링을 중단합니다.

신고 본문은 `{ "scanId": "검사 ID" }`, 응답은 `{scanId,reportCount,isReported,reportedByUser}`입니다. 완료된 악성 판정만 접수하며 그 외 판정은 409입니다. 집계는 같은 정규화 URL에 대해 **현재 서버 프로세스가 접수한 횟수**입니다. `reportedByUser`는 해당 검사 ID에서 접수했음을 뜻하며 인증된 사용자 신원이 아닙니다. 새 검사 ID에서는 별도로 접수할 수 있습니다. 외부 평판 데이터베이스나 운영용 사용자 중복 방지 수치로 해석하지 마세요.

상세 요청·응답 변환과 오류 처리는 [프런트 API 안내](docs/frontend-api.md), Worker 계약은 [Worker 안내](worker/README.md)에 있습니다. 위 표는 `app.main:app`의 로컬 계약이며 로컬 `/openapi.json`으로 확인합니다. 공개 배포용 `app.public_api:app`는 별도로 `POST /api/analyze`, `GET /api/health`, `GET /api/capabilities`를 제공합니다.

## 정적 검사와 판정 한계

Google Safe Browsing v5가 위협 정보를 제공합니다. OpenPhish·일반 브랜드 유사도 엔진은 연결하지 않았습니다. 공개 구성은 요청 URL을 조회하고, 로컬 격리 모드는 실제 방문 후 최종 URL도 조회하며 Google 위협 근거를 보존합니다. Google 조회 성공의 빈 결과는 해당 조회 범위 내 미탐지이며, 키 누락·권한 오류·쿼터·타임아웃·비정상 응답은 `failed/matched:null`입니다. 성공 응답만 Google의 `cacheDuration` 동안 제한된 메모리 캐시에 보관합니다.

쿼리 등을 포함한 검사 URL이 Google에 전송됩니다. 카메라 영상·QR 이미지는 보내지 않습니다. Google 키는 API 서버만 사용하며 Docker Worker와 정적 배포 출력에 포함하지 않습니다. 실제 인증 토큰·계정 정보가 포함된 주소는 시연에 사용하지 마세요. 참고: [Google Safe Browsing v5 URL 검색](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search).

판정은 Google 위협 탐지 → 선택한 브랜드와 관찰된 로그인 필드의 불일치 → 필요한 검사 완료 시 범위 내 미탐지 → 그 외 확인 불가 순서로 처리합니다. **Phishpedia 모델 가중치와 브랜드 자료는 현재 통합 실행에 없으며 모델 결과를 판정에 사용하지 않습니다.** DOM·네트워크 관찰은 실제 정보 유출을 검증한 것과 다릅니다. 로그인·결제·폼 자동 제출은 하지 않습니다.

Docker는 VM 수준의 격리를 보증하지 않습니다. 기본 로컬 실행의 무해한 방문과 네트워크 단절 확인을 임의의 악성 사이트에 대한 운영 안전성 검증으로 확대 해석하지 마세요. Worker 이미지는 호스트 파일·Docker 소켓·Google 키를 마운트하지 않습니다. 자세한 실행 제한은 [Worker 안내](worker/README.md)를 참고하세요.

## Vercel 프런트·정적 검사 API 배포

기존 정적 프런트 배포에서 같은 출처의 정적 검사 API를 함께 배포하는 구조로 변경했습니다. 프런트 파일은 CDN의 `dist/`, Python API는 `api/analyze.py`, `api/health.py`, `api/capabilities.py`의 세 네이티브 Functions로 배포합니다. 별도 rewrite나 로컬 loopback API 주소를 사용하지 않습니다. 각 진입점은 `app/public_api.py`의 앱을 사용하며 Docker·로컬 메모리 작업 저장소를 가져오지 않습니다.

저장소의 `vercel.json`은 다음 정적 설정을 사용합니다.

| 설정 | 값 |
| --- | --- |
| Framework Preset | Other (`framework: null`) |
| Install Command | 없음 |
| Build Command | `node scripts/prepare-vercel.mjs --public` |
| Output Directory | `dist` |
| Python Functions | `api/analyze.py`, `api/health.py`, `api/capabilities.py` |
| API 제한 시간 | 함수 최대 30초, 위협 조회 최대 12초 |

복사 스크립트는 `index.html`, `src/`의 JS·CSS, `assets/`의 허용된 이미지만 정적 출력에 담습니다. `--public`은 생성된 `dist/src/deployment-config.js`에 `direct/static` 설정을 기록하며 소스의 로컬 `job/sandbox` 기본값을 바꾸지 않습니다. Python 코드는 Vercel이 별도로 빌드합니다. `.vercelignore`는 공개 API가 가져오는 Python 소스와 실행 의존성만 추가로 허용하며 수정 중인 Worker·테스트·비밀 파일은 제외합니다. 프런트에 런타임 라이브러리나 번들러를 추가하지 않습니다.

Google 키는 Vercel 서버 환경 변수 `GOOGLE_SAFE_BROWSING_API_KEY`로만 설정합니다. Production·Preview의 민감한 값으로 관리하고 정적 파일·배포 소스·문서에 기록하지 않습니다. API 응답은 `no-store`이며 16KiB 요청 본문 제한과 브라우저 출처 검증을 적용합니다. 이 출처 검증은 사용자 인증이나 분산 요청 제한을 대신하지 않습니다.

공개 배포 구성을 로컬에서 재현하려면 두 터미널에서 실행합니다.

```sh
# 터미널 1: 서버 전용 Google 키가 준비된 환경
.venv/bin/python -m uvicorn app.public_api:app --host 127.0.0.1 --port 8001 --no-access-log
```

```sh
# 터미널 2: 공개 프런트 설정으로 API를 같은 출처에 연결
node scripts/prepare-vercel.mjs --public
PORT=8086 QR_GUARD_API=http://127.0.0.1:8001 node scripts/dev-server.mjs --public
```

[공개 구성 로컬 확인](http://127.0.0.1:8086/)에서 `GET /api/health`와 실제 검사를 확인합니다. 이는 공개 배포의 로컬 재현이며 휴대전화 하드웨어 촬영 검증을 대신하지 않습니다.

## URL별 고정 판정 시연

기본은 비활성화입니다. `src/data/url-verdict-demo.js`의 `// enabled = true;` 한 줄만 주석 해제하면 다음 두 HTTPS 주소에 고정된 피싱 결과를 표시합니다. 변경 후 실행 중인 페이지는 새로고침하고, 배포본에 반영하려면 정적 파일을 다시 패키징해야 합니다.

| 입력 URL | 표시할 판정 사유 |
| --- | --- |
| `https://realistic-phishing-website.vercel.app/` | 로고와 주소 불일치 |
| `https://fake-phishing-website.vercel.app/` | 동적 판단에서 감지 |

마지막 `/` 유무와 호스트 대소문자는 URL 정규화로 처리합니다. 다른 경로·쿼리·해시·하위 도메인·프로토콜은 대상이 아니며 기존 검사 API를 사용합니다. QR 인식과 수동 입력에 동일하게 적용하고, URL 파라미터나 브라우저 저장소로 활성화하지 않습니다.

활성화한 두 주소는 검사 API나 목적지에 요청하지 않고 로컬 결과만 표시합니다. 로딩·결과에 “데모 응답 · 실제 검사 아님”을 유지하며 실제 로고 비교·동적 분석·방문·촬영·신고를 수행하지 않습니다. 신고 건수·도착 주소를 만들지 않고 사이트 접속·신고 동작을 제공하지 않습니다. 해당 줄을 다시 주석 처리하면 기존 API 흐름으로 복귀합니다.

## 검증

```sh
.venv/bin/python -m pytest -q
```

프런트 테스트는 소스를 제공하는 정적/개발 서버에서 [서비스 검사](http://127.0.0.1:8080/tests/frontend/services.html)와 [UI 검사](http://127.0.0.1:8080/tests/frontend/ui.html)를 엽니다. 테스트는 공개 `dist/`에 포함하지 않습니다. API와 새 창을 대역으로 처리하며 실제 악성 사이트를 방문하지 않습니다. 공개 API 분리 후 Python 416개, 프런트 서비스 43개·UI 18개를 확인했습니다. 이전 Docker 통합 작업의 실제 Google·PNG·신고 검증은 [실제 로컬 연동 검증](docs/integration-verification.md)에 별도로 기록했습니다.

회귀 검사와 공개 주소의 실제 HTTP 검증을 구분해 기록합니다. 실제 하드웨어 카메라 QR 판독, 모든 휴대전화의 QR 지원, 임의 악성 사이트 운영 안전성은 별도 검증 대상입니다. 사용자의 검사 URL·결과·이미지·신고 상태는 브라우저 저장소에 기록하지 않습니다. Shadow DOM 검사에는 `shadowRoot` 순회 또는 이를 지원하는 도구가 필요합니다.
