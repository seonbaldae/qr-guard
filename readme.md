# QR Guard

QR에 담긴 주소를 사용자 기기에서 바로 열지 않고 먼저 검사하는 해커톤 서비스입니다. 공개 서비스는 요청별 클라우드 VM에서 Worker를 실행해 사이트 화면과 관찰 결과를 제공합니다. 기존 로컬 Docker 개발 경로도 유지합니다.

## 구현된 흐름

- **모바일 프런트:** HTML·CSS·순수 JavaScript ES Modules, Web Components와 open Shadow DOM으로 QR 촬영 → 검사 중 → 결과의 세 화면을 제공합니다. QR 인식은 브라우저의 `BarcodeDetector`를 사용하며 직접 입력도 지원합니다. 프로토콜 없는 웹 주소에는 입력 단계에서만 `https://`를 보완합니다.
- **공개 API 구성:** `app/public_api.py`가 같은 출처의 `POST /api/analyze` 요청 안에서 정적 검사와 설정된 클라우드 관찰을 처리합니다. 클라우드 실행 소스와 검증 게이트가 준비되지 않은 경우 정적 검사 범위로 동작합니다. 서버리스 인스턴스의 메모리 작업 폴링이나 로컬 Docker 데몬에 의존하지 않습니다.
- **클라우드 Worker 구성:** 이미지 또는 스냅샷 중 하나로 검사마다 임시 VM을 만듭니다. 현재 공개 서비스는 `worker/cloud/` runner·고정 의존성을 준비한 Sandbox 스냅샷을 사용하며, 2026-10-31 실제 Chromium 방문과 PNG·최종 URL·DOM·네트워크 관찰 응답을 확인했습니다. VCR 이미지 게시는 blob commit 시간 초과로 완료되지 않았습니다. 현재 실행은 Docker 엔진이나 VCR 이미지 배포가 아닙니다.
- **로컬 통합 API:** `app/main.py`는 기존 작업 생성·조회·PNG 조회·신고 접수를 처리합니다. 로컬 프런트는 작업 완료를 폴링합니다. 모델 추론을 포함한 프런트 전체 검사 제한은 270초입니다.
- **정적 검사:** URL 구조와 Google Safe Browsing v5를 확인합니다. Google 조회 실패를 미탐지로 바꾸지 않으며 키는 서버에서만 사용합니다. 검사 시작 전 URL이 Google에 전송된다는 안내를 제공합니다.
- **로컬 Docker Worker:** Playwright·Chromium이 별도 컨테이너에서 페이지를 방문하고 실제 PNG·최종 URL·DOM 및 네트워크 관찰을 반환합니다. 로컬 통합 실행은 `--network none`을 유지하고 호스트 API가 제한된 `docker exec` 전송으로 Worker 작업을 생성·조회합니다. 이 기존 팀 개발 경로는 클라우드용 단일 실행 이미지와 분리합니다.
- **로컬 신고:** 완료된 악성 판정에 대한 신고를 현재 로컬 서버 프로세스에서 접수합니다. 같은 검사 ID의 중복 요청은 한 번만 집계합니다. 공개 배포에는 공유 저장소가 없으므로 이 메모리 집계를 사용하지 않습니다.

정상 완료 결과에만 사용자가 직접 누를 수 있는 **사이트 들어가기** 버튼을 제공합니다. 피싱·의심·확인 불가 결과에는 접속 동작을 제공하지 않습니다. 알려진 위협이 발견되면 Worker 방문을 생략합니다. 미탐지는 완전한 안전이나 공식 사이트 인증을 뜻하지 않습니다.

## 다른 휴대전화에서 사용할 공개 서비스

[QR Guard 열기](https://qr-guard-five.vercel.app/). 2026-10-31 Vercel Production `dpl_6yyy5mB1ydQqDPATJswgh6oeQEzK`가 `READY`이며, 공개 HTTPS API에서 Sandbox 스냅샷 기반 실제 방문·PNG 회수를 확인했습니다. Google 조회도 실제 연결됐습니다. 신고는 공유 저장소 미연결로 준비 중입니다.

공개 `example.com` 검사에서 약 8.9초 후 실제 최종 URL과 같은 검사 ID의 390×844 PNG를 받았고 이미지 디코딩도 확인했습니다. 브랜드 모델은 아직 연결되지 않아 최종 판정은 `unknown`입니다. Google 공식 피싱 테스트 주소는 약 1.8초 후 `malicious`로 응답하고 격리 방문을 생략해 PNG를 제공하지 않았습니다. 현재 검증은 [클라우드 미리보기 기록](docs/cloud-preview.md), 앞서 완료한 정적 검사 배포 이력은 [공개 배포 검증](docs/public-deployment.md)에 구분해 기록합니다.

| 구분 | 기존 공개 정적 배포 | 현재 공개 클라우드 미리보기 | 로컬 Docker 통합 구성 |
| --- | --- | --- | --- |
| 검사 요청 | `POST /api/analyze`, 요청 안에서 완료 | 같은 `POST /api/analyze`에서 요청별 VM 실행·회수 | `POST /api/scans`, 상태 폴링 |
| 검사 범위 | URL 구조·Google Safe Browsing | 정적 검사·격리 방문·DOM·네트워크 관찰 | 정적 검사·격리 방문·DOM·네트워크 관찰 |
| 실제 방문·이미지 | 방문하지 않음 | 스냅샷 VM에서 실제 PNG를 회수한 경우만 제공 | Worker가 확인한 경우에만 제공 |
| 최종 URL | `null`, 최종 목적지 미확인 | 실행 결과에서 확인한 실제 주소만 제공 | 실제 방문으로 관찰한 주소 |
| 신고 | 미제공·건수 미확인 | 미제공·건수 미확인 유지 | 단일 프로세스 메모리에 접수 |

공개 서비스는 격리된 환경의 사이트 화면을 확인합니다. 클라우드 설정이 없거나 검증 게이트가 꺼진 정적 구성에서는 주소만 검사한다는 안내를 표시합니다. Google 목록 미일치와 화면 촬영 성공만으로 정상 판정하지 않으며 미확인 브랜드 분석은 `unknown`으로 보류하고 사이트 진입을 제공하지 않습니다. 알려진 위협은 위험 경고로 표시하고, 확인하지 않은 최종 목적지나 스크린샷을 만들지 않습니다. `reportAvailable: false`이면 신고 건수는 `null`로 유지하고 “신고 기능 준비 중”을 표시합니다.

로컬 Docker 실행 코드와 수정 중인 기존 Worker 작업 서버를 공개 API 함수에 그대로 넣지 않습니다. 클라우드용 이미지 또는 준비한 스냅샷으로 공개 API가 VM을 생성하고 결과를 회수한 뒤 정리합니다. 스냅샷 경로는 Docker 엔진을 실행하는 방식이 아닙니다. PNG는 검사 ID·MIME·시그니처·용량을 확인하는 `previewImage`로 전달해 후속 이미지 조회용 메모리 저장소에 의존하지 않습니다. 클라우드 VM에서 사설망·메타데이터 차단과 IPv6 비활성화 확인을 마친 뒤 Chromium을 실행하며, 키·SDK 자격 증명은 VM에 넘기지 않습니다. 재배포 절차와 현재 검증 상태는 [클라우드 미리보기 구성](docs/cloud-preview.md)을 참고하세요.

공개 Phishpedia 연동은 준비·배포 중입니다. 브라우저가 얻은 PNG를 별도의 네트워크 차단 모델 VM에서 분석하고 식별 브랜드의 기준 도메인과 실제 도착 도메인을 비교합니다. 근거가 있는 불일치는 `suspicious`, 브랜드 미식별·미설정·분석 실패는 `unknown`으로 처리합니다. 브랜드 일치만으로 공식 운영이나 안전을 인증하지 않으며, 알려진 Google 위협의 위험 판정은 유지합니다. 사용자의 요청으로 이번 연동의 테스트·샘플 추론·기능 검증은 실행하지 않습니다. 기존 공개 방문·PNG 검증 이력은 모델 탐지 성공을 뜻하지 않습니다.

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

Google Safe Browsing v5가 위협 정보를 제공합니다. OpenPhish·일반 브랜드 유사도 엔진은 연결하지 않았습니다. 정적 구성은 요청 URL을 조회하고, 클라우드·로컬 격리 구성은 실제 방문으로 최종 URL을 확인한 경우 해당 주소도 조회하며 Google 위협 근거를 보존합니다. Google 조회 성공의 빈 결과는 해당 조회 범위 내 미탐지이며, 키 누락·권한 오류·쿼터·타임아웃·비정상 응답은 `failed/matched:null`입니다. 성공 응답만 Google의 `cacheDuration` 동안 제한된 메모리 캐시에 보관합니다.

쿼리 등을 포함한 검사 URL이 Google에 전송됩니다. 카메라 영상·QR 이미지는 보내지 않습니다. Google 키는 API 서버만 사용하며 Docker Worker와 정적 배포 출력에 포함하지 않습니다. 실제 인증 토큰·계정 정보가 포함된 주소는 시연에 사용하지 마세요. 참고: [Google Safe Browsing v5 URL 검색](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search).

로컬 통합의 판정은 Google 위협 탐지 → 격리 브라우저 촬영 → Phishpedia 로고 식별과 기준 도메인 비교 → 선택한 브랜드와 관찰된 로그인 필드의 불일치 → 필요한 검사 완료 시 범위 내 미탐지 순서로 처리합니다. 식별한 브랜드의 기준 도메인과 실제 도착 도메인이 다르면 사칭 의심으로 차단합니다. 브랜드 미식별·분석 실패를 미탐지로 바꾸지 않습니다. 공개 구성은 같은 목적의 모델을 별도의 네트워크 차단 스냅샷으로 준비하며, 로컬 모델의 존재를 공개 연결 완료로 설명하지 않습니다. DOM·네트워크 관찰은 실제 정보 유출을 검증한 것과 다릅니다. 로그인·결제·폼 자동 제출은 하지 않습니다.

Docker는 VM 수준의 격리를 보증하지 않습니다. 기본 로컬 실행의 무해한 방문과 네트워크 단절 확인을 임의의 악성 사이트에 대한 운영 안전성 검증으로 확대 해석하지 마세요. Worker 이미지는 호스트 파일·Docker 소켓·Google 키를 마운트하지 않습니다. 자세한 실행 제한은 [Worker 안내](worker/README.md)를 참고하세요.

## Vercel 프런트·API와 클라우드 Worker 배포

기존 정적 프런트 배포에서 같은 출처의 API를 함께 배포하는 구조로 변경했습니다. 프런트 파일은 CDN의 `dist/`, Python API는 `api/analyze.py`, `api/health.py`, `api/capabilities.py`의 세 네이티브 Functions로 배포합니다. 별도 rewrite나 로컬 loopback API 주소를 사용하지 않습니다. 각 진입점은 `app/public_api.py`의 앱을 사용하며 클라우드 활성화 시 `app/cloud_worker.py`가 고정 이미지 또는 스냅샷으로 요청별 VM을 생성합니다. 로컬 Docker CLI나 메모리 작업 저장소를 가져오지 않습니다.

현재 저장소의 `vercel.json`은 클라우드 미리보기를 위한 다음 배포 구성을 사용합니다. 설정 파일의 존재와 실제 공개 배포 성공을 구분합니다.

| 설정 | 값 |
| --- | --- |
| Framework Preset | Other (`framework: null`) |
| Install Command | 없음 |
| Build Command | `node scripts/prepare-vercel.mjs --public --cloud-preview` |
| Output Directory | `dist` |
| Python Functions | `api/analyze.py`, `api/health.py`, `api/capabilities.py` |
| API 제한 시간 | 함수 최대 300초, 프런트 전체 요청 최대 270초 |

복사 스크립트는 `index.html`, `src/`의 JS·CSS, `assets/`의 허용된 이미지만 정적 출력에 담습니다. `--public --cloud-preview`는 생성된 `dist/src/deployment-config.js`에 `direct/sandbox` 설정을 기록하며, `--public`만 사용하면 이전 정적 `direct/static` 구성을 만듭니다. 소스의 로컬 `job/sandbox` 기본값은 바꾸지 않습니다. Python 코드는 Vercel이 별도로 빌드합니다. `.vercelignore`는 공개 API가 가져오는 Python 소스와 실행 의존성만 추가로 허용하며 Worker 이미지 또는 스냅샷은 별도로 준비합니다. 프런트에 런타임 라이브러리나 번들러를 추가하지 않습니다.

Google 키는 Vercel 서버 환경 변수 `GOOGLE_SAFE_BROWSING_API_KEY`로만 설정합니다. Production·Preview의 민감한 값으로 관리하고 정적 파일·배포 소스·문서에 기록하지 않습니다. API 응답은 `no-store`이며 16KiB 요청 본문 제한과 브라우저 출처 검증을 적용합니다. 이 출처 검증은 사용자 인증이나 분산 요청 제한을 대신하지 않습니다.

클라우드 Worker는 `QR_GUARD_CLOUD_WORKER_IMAGE=<VCR의 @sha256 digest>` 또는 `QR_GUARD_CLOUD_WORKER_SNAPSHOT=<준비한 snap_ ID>` 중 정확히 하나를 서버에 설정합니다. 두 소스를 함께 설정하면 구성을 거부합니다. 선택한 소스에서 실제 VM 방화벽·IPv6 비활성화·Chromium 샌드박스·PNG 회수를 검증한 후에만 공통 게이트 `QR_GUARD_CLOUD_WORKER_VERIFIED=true`를 설정합니다. 소스가 없거나 미검증이면 정적 검사로 동작하고, 활성화 후 방문 실패는 `unknown`으로 보류합니다. 요청 VM 정리는 소스 스냅샷을 삭제하지 않으며, 플래그를 켜는 작업이 격리 정책을 만들어 주지는 않습니다.

Phishpedia는 별도의 서버 전용 `QR_GUARD_PHISHPEDIA_SNAPSHOT=<모델을 준비한 snap_ ID>`로 설정합니다. 원본에는 고정 코드·모델 가중치·기준 로고·특징 캐시만 담고 검사 URL·PNG·결과·자격 증명은 담지 않습니다. 요청별 모델 VM은 `deny-all` 네트워크에서 PNG와 실제 최종 URL을 분석하며 브라우저 VM의 외부 접속 권한을 공유하지 않습니다. 모델 설정이나 배포 완료와 실제 탐지 정확도 검증은 별개입니다.

공개 배포 구성을 로컬에서 재현하려면 두 터미널에서 실행합니다.

```sh
# 터미널 1: 서버 전용 Google 키가 준비된 환경
.venv/bin/python -m uvicorn app.public_api:app --host 127.0.0.1 --port 8001 --no-access-log
```

```sh
# 터미널 2: 공개 프런트 설정으로 API를 같은 출처에 연결
node scripts/prepare-vercel.mjs --public --cloud-preview
PORT=8086 QR_GUARD_API=http://127.0.0.1:8001 node scripts/dev-server.mjs --public
```

[공개 구성 로컬 확인](http://127.0.0.1:8086/)에서 `GET /api/health`와 실제 검사를 확인합니다. 클라우드 이미지/스냅샷 설정·검증 게이트·서버 SDK 인증이 준비되지 않았다면 실제 VM 방문까지 확인한 것은 아닙니다. 이 로컬 재현은 공개 배포나 휴대전화 하드웨어 촬영 검증을 대신하지 않습니다.

## URL별 고정 판정 시연

기본은 비활성화입니다. `src/data/url-verdict-demo.js`의 `// enabled = true;` 한 줄만 주석 해제하면 다음 두 HTTPS 주소에 고정된 피싱 결과를 표시하고, 그 외 모든 유효한 HTTP(S) URL에는 “피싱 사이트가 아니에요 (모의 결과)”를 표시합니다. 변경 후 실행 중인 페이지는 새로고침하고, 배포본에 반영하려면 정적 파일을 다시 패키징해야 합니다.

| 입력 URL | 표시할 판정 사유 |
| --- | --- |
| `https://realistic-phishing-website.vercel.app/` | 로고와 주소 불일치 |
| `https://fake-phishing-website.vercel.app/` | 동적 판단에서 감지 |

마지막 `/` 유무와 호스트 대소문자는 URL 정규화로 처리합니다. 다른 경로·쿼리·해시·하위 도메인·프로토콜을 포함해 두 주소와 일치하지 않는 유효한 URL은 비피싱 모의 결과가 됩니다. 잘못된 URL·미지원 프로토콜은 기존 입력 검증에서 거부합니다. QR 인식과 수동 입력에 동일하게 적용하고, URL 파라미터나 브라우저 저장소로 활성화하지 않습니다.

활성화 중에는 모든 URL에 대해 검사 API나 목적지에 요청하지 않고 로컬 결과만 표시합니다. 로딩·결과에 “데모 응답 · 실제 검사 아님”을 유지하며 실제 로고 비교·동적 분석·방문·촬영·신고를 수행하지 않습니다. 신고 건수·도착 주소를 만들지 않고 사이트 접속·신고 동작을 제공하지 않습니다. 해당 줄을 다시 주석 처리하면 모든 URL이 기존 API 흐름으로 복귀합니다.

기존 서비스·UI 회귀 검사는 기본 비활성 상태에서 실행합니다. 활성 상태는 주석 한 줄을 해제한 로컬 임시 사본에서 `tests/frontend/url-verdict-demo.html`을 열어 별도로 검증합니다. 이 전용 검사는 스위치 활성화·두 피싱 사유·나머지 URL의 비피싱 결과·무통신·잘못된 입력·취소·초기화를 확인합니다.

## 검증

```sh
.venv/bin/python -m pytest -q
```

프런트 테스트는 소스를 제공하는 정적/개발 서버에서 [서비스 검사](http://127.0.0.1:8080/tests/frontend/services.html)와 [UI 검사](http://127.0.0.1:8080/tests/frontend/ui.html)를 엽니다. 테스트는 공개 `dist/`에 포함하지 않습니다. API와 새 창을 대역으로 처리하며 실제 악성 사이트를 방문하지 않습니다. 공개 API 분리 후 Python 416개, 프런트 서비스 43개·UI 18개를 확인했습니다. 이전 Docker 통합 작업의 실제 Google·PNG·신고 검증은 [실제 로컬 연동 검증](docs/integration-verification.md)에 별도로 기록했습니다.

회귀 검사와 공개 주소의 실제 HTTP 검증을 구분해 기록합니다. 실제 하드웨어 카메라 QR 판독, 모든 휴대전화의 QR 지원, 임의 악성 사이트 운영 안전성은 별도 검증 대상입니다. 사용자의 검사 URL·결과·이미지·신고 상태는 브라우저 저장소에 기록하지 않습니다. Shadow DOM 검사에는 `shadowRoot` 순회 또는 이를 지원하는 도구가 필요합니다.
