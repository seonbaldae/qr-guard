# 휴대전화용 공개 배포

2026-10-31에 기존 Vercel 프로젝트 `qr-guard`에 Production 배포를 완료했습니다.

- 접속: [QR Guard](https://qr-guard-five.vercel.app/)
- 배포 ID: `dpl_5ML87NX2DqsfXX5EX2fJzf49fg4M` (`READY`)
- 실행 환경: Node.js 24 빌드, Python 3.12 API, HTTPS
- 배포 소스: 공개 프런트와 정적 API의 명시적인 43개 파일. Worker 파일은 포함하지 않았습니다.

## 다른 사람이 사용할 수 있는 기능

휴대전화에서 공개 주소를 열어 카메라를 켜거나 주소를 직접 입력하면 Vercel의
`POST /api/analyze`가 Google Safe Browsing과 URL 구조 검사를 수행합니다.
Google 목록에 없는 주소도 화면과 동작을 검사하지 않았으므로 판단을 보류하고
이동 버튼을 제공하지 않습니다. 알려진 위협은 위험으로 경고합니다. 검사 전에는 사용자 브라우저가
QR 목적지에 접속하지 않습니다.

**현재 공개 버전은 주소 검사만 수행합니다.** Docker Worker가 수정 중이므로
화면 미리보기·DOM·네트워크 관찰·최종 목적지는 공개 검사 범위에 포함하지 않습니다.
결과에 `mode: static`, `analysisScope: static`, `finalUrl: null`을 명시합니다.
공유 신고 저장소도 아직 연결하지 않아 신고 버튼은 준비 중이며 건수는 `null`입니다.
로컬 메모리의 신고 수를 공개 통계로 사용하지 않습니다.

공개 서비스는 개발자의 컴퓨터·로컬 API·Docker 실행 여부에 의존하지 않습니다.
기존 로컬 `app.main`과 `scripts/run-local.py`의 격리 방문 흐름은 그대로 유지합니다.
Worker 소스를 바꾸더라도 공개 API가 해당 모듈을 가져오거나 실행하지 않습니다.

## 배포 구성

- `vercel.json`: 정적 `dist`와 `api/*.py` 함수, API 30초 상한, 카메라 권한·캐시 헤더.
- `scripts/prepare-vercel.mjs --public`: 정적 파일만 복사하고 공개용 `direct/static` 설정을 생성합니다.
- `api/analyze.py`, `health.py`, `capabilities.py`: 파일 경로와 같은 API를 제공하며 rewrite가 필요 없습니다.
- `app/public_api.py`: 한 요청에서 검사를 완료합니다. 서버리스 인스턴스 사이의 메모리 작업·폴링에 의존하지 않습니다.
- Google 키: Vercel의 서버 전용 Secret 환경 변수 `GOOGLE_SAFE_BROWSING_API_KEY`. 프런트 소스에 넣지 않습니다.
- `.vercelignore`: 공개 소스만 허용합니다. `!api`처럼 디렉터리 이름 자체를 허용해야 합니다. 후행 슬래시만 있는 `!api/`는 빌더가 디렉터리를 탐색하기 전에 제외하여 `unused_function` 오류를 만들 수 있습니다.

운영 기능의 제공 여부는 `GET /api/capabilities`에서 확인합니다. 현재는
`previewAvailable: false`, `reportAvailable: false`입니다. Docker 연동을 켜려면
안정화된 격리 서버와 API 계약, 공유 작업·이미지·신고 저장소를 별도로 검증해야 합니다.
로컬 Docker 소켓이나 개발용 포트를 공개하지 않습니다.

## 실제 확인 결과

| 확인 | 결과 |
| --- | --- |
| 쿠키·로그인 없는 `GET /api/health` | 200, `direct/static` |
| `https://example.com/` 검사 | Google `checked`, `matched: false`; 초기 배포의 `no_known_threat`를 `unknown` 판단 보류로 보완 |
| Google 공식 피싱 테스트 주소 검사 | Google `checked`, `matched: true`, `malicious` |
| 공개 브라우저 화면 | 주소 입력 → 로딩 → 판단 보류 또는 위험 경고 표시 |
| 위험 결과 | 접속 버튼 없음, 신고 준비 중·건수 미확인 |
| 다른 Origin의 POST | 403 |
| 잘못된 프로토콜 | 422 |
| `/.env`, `/app/public_api.py`, `/worker/worker.cjs` | 모두 404 |
| 브라우저 회귀 | 서비스 43개, UI 18개 통과 |
| Python 회귀 | 416개 통과. Google 대역 테스트와 위 실제 공개 조회를 구분합니다. |

모바일 390px 화면을 확인했으며 콘솔 오류·경고가 없었습니다. 실제 휴대전화의
하드웨어 QR 촬영은 이번 확인에 포함하지 않았습니다. HTTPS는 카메라 사용에 필요한
조건이며 QR 판독에는 브라우저의 `BarcodeDetector` 지원과 사용자 권한도 필요합니다.
미지원 브라우저에서는 주소 직접 입력을 사용합니다.

Google 목록에 없는 신규 사칭이나 화면·동작에만 드러나는 위험은 놓칠 수 있습니다.
미탐지는 사이트 안전이나 공식 운영 여부의 인증이 아닙니다.

2026-10-31에 자체 모의 사칭 주소가 Google 목록 미일치 후 정상 계열로 표시되는 경로를 확인했습니다.
공개 정적 검사의 목록 미일치는 제공자 결과로 보존하되 최종 판정을 `unknown`으로 보류하도록 보완합니다.
이 변경은 정상 오인과 접속 유도를 줄이는 조치입니다. Docker의 공개 배포나 시각·행위 기반 탐지를
추가한 변경은 아닙니다.

관련 플랫폼 문서: [Python 파일 기반 함수](https://vercel.com/docs/functions/runtimes/python/api-directory),
[Python 실행 환경](https://vercel.com/docs/functions/runtimes/python),
[배포 설정](https://vercel.com/docs/project-configuration/vercel-json).
