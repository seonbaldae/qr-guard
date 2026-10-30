# Docker 브라우저 Worker

`worker.cjs`가 Playwright·Chromium으로 페이지를 방문해 PNG와 DOM·네트워크·리다이렉트 관찰을 반환합니다. FastAPI의 `app/worker.py`가 작업 생성·폴링·이미지 조회를 실제로 연결합니다. `Phishpedia` 관련 파일은 별도의 실험 자료이며 현재 실행 경로에서 모델 판정을 제공하지 않습니다.

## 권장 실행

저장소 루트에서 Docker Desktop과 Python 의존성·Node.js를 준비한 뒤 실행합니다.

```sh
.venv/bin/python scripts/run-local.py
```

이미지가 준비됐다면 `--skip-build`를 사용할 수 있습니다. 기본 모드는 Worker 안의 무해한 `http://127.0.0.1:4000/demo/normal`만 방문합니다. 프런트는 [로컬 화면](http://127.0.0.1:8080/)에서 직접 입력으로 이 주소를 검사할 수 있습니다. 이미지 파일을 fixture로 대신하는 흐름이 아니라 Chromium이 실제로 촬영한 PNG를 API가 검증해 제공합니다.

실행기는 다음 설정을 사용하고 실제 컨테이너 설정이 맞는지 확인합니다.

- 네트워크 `none`, 공개 포트 없음, 호스트 디렉터리·Docker 소켓 마운트 없음.
- 비루트 `pwuser`, 읽기 전용 루트 파일시스템, 쓰기 가능한 임시 `/tmp`와 공유 메모리.
- capabilities 전체 제거 후 Chromium 샌드박스 실행에 필요한 `SYS_CHROOT`만 추가, `no-new-privileges`, 저장소의 seccomp 프로필 적용.
- 메모리 1GiB, CPU 1개, PID 256개, 임시 파일시스템·공유 메모리 제한.
- `chromiumSandbox: true`로 실행하며 `--no-sandbox`를 사용하지 않음.
- Google 키는 API 서버만 사용하고 Worker에 전달하지 않음.

API는 컨테이너 안의 loopback HTTP 서버에 제한된 `docker exec` 요청으로 접근합니다. 이 방식으로 Worker 포트를 호스트나 외부에 공개하지 않습니다. API 프로세스의 Docker 제어 권한은 신뢰된 호스트 권한이므로, API를 그대로 공개하는 운영 구성으로 해석하지 마세요.

## 공개 주소 미리보기 옵션

```sh
.venv/bin/python scripts/run-local.py --skip-build --public-preview
```

처음 실행하거나 이미지가 바뀌면 `--skip-build`를 빼고 실행합니다. 기존 컨테이너가 다른 모드·이미지라면 실행기가 실패하며 자동 교체하지 않습니다. 실행기가 새로 만든 컨테이너는 종료 시 정리하고 기존 컨테이너는 보존합니다. 프런트와 API는 계속 호스트 loopback에서만 실행됩니다. 이 옵션으로 Vercel이나 공개 API에 배포하지 않습니다.

공개 모드에서도 Docker 네트워크는 `none`입니다. `worker/egress-tunnel.cjs`가 컨테이너 loopback의 프록시를 만들고, `app/egress_tunnel.py`가 `docker exec` 표준 입출력 터널을 통해 외부 TCP 연결을 중계합니다. Worker에는 직접 외부 소켓이나 호스트 네트워크를 허용하지 않습니다.

- 모든 연결 대상의 DNS 응답을 검사하고 내부·사설·loopback·링크 로컬·메타데이터·특수 주소를 거부합니다. 검사한 숫자 IPv4 주소로 TCP 연결을 고정해 연결 시 DNS를 다시 해석하지 않습니다.
- HTTP 80·HTTPS 443만 허용합니다. IPv6 전용 대상·IPv6 리터럴·다른 포트는 지원하지 않습니다. 리다이렉트와 하위 리소스도 같은 연결 경로를 거칩니다.
- 연결 수·누적 연결 시도·바이트 수·수명에 상한을 둡니다. 중계가 거부한 연결이 있으면 페이지 관찰이 불완전한 것으로 전달합니다.
- TLS는 Chromium과 대상 서버 사이에 유지되며 인증서 검증을 끄지 않습니다. 중계기는 HTTPS 내용을 복호화하지 않습니다.
- Chromium 라우팅에서 GET·HEAD의 읽기 요청만 허용하고 다른 메서드·요청 본문·다른 페이지의 요청을 차단합니다. WebSocket은 별도로 닫고 서비스 워커·다운로드도 제한합니다. HTTPS 내부 메서드 제한은 브라우저 정책에 의존하므로 침해된 브라우저를 통제하는 독립적인 HTTP 방화벽은 아닙니다.

공개 `example.com`을 대상으로 실제 Google 조회·최종 URL·PNG·프런트 결과 표시를 확인했고, 컨테이너의 직접 메타데이터 접근 차단도 확인했습니다. 이 기능은 제한된 해커톤용 로컬 미리보기입니다. VM 수준 격리, 브라우저 탈출 방어, 임의 악성 사이트의 운영 안전성 검증이 완료됐다고 설명하지 마세요.

## 이미지 빌드

통합 실행기가 이미지를 준비하지만 별도 빌드가 필요하면 저장소 루트에서 실행합니다.

```sh
docker build -f worker/Dockerfile -t seonbaldae-browser worker
docker build -f worker/Dockerfile.worker -t qr-guard-worker:local worker
```

`Dockerfile`은 브라우저 기본 이미지, `Dockerfile.worker`는 관찰 모듈과 Worker 서버를 담습니다. `browser.cjs`는 자체 HTML을 촬영하는 초기 확인용 코드이며 API 통합의 진입점은 `worker.cjs`입니다. 초기 확인 스크립트의 출력만으로 실제 API 연동을 검증했다고 보고하지 마세요.

## 내부 작업 계약

| 내부 요청 | 용도 |
| --- | --- |
| `GET /internal/health` | Worker 프로세스 생존 확인 |
| `POST /internal/jobs` | `{scanId,url,timeoutMs}` 작업 생성 |
| `GET /internal/jobs/{scanId}` | 같은 검사 ID의 작업·관찰 상태 조회 |
| `GET /internal/jobs/{scanId}/screenshot` | 준비된 PNG 조회 |

공개 API와 Worker는 같은 `scanId`를 사용합니다. API 어댑터는 생성 응답·폴링의 ID 일치, 상태, 최종 주소, HTTP 상태, 이미지 준비 여부와 MIME을 검사합니다. 응답은 6MiB, PNG는 4MiB·1600만 픽셀 이내로 제한하고 PNG 청크뿐 아니라 실제 픽셀 디코딩도 확인합니다. Worker의 임의 오류 메시지나 URL 토큰을 외부에 그대로 직렬화하지 않습니다.

공개 `sandboxAnalysis`는 이 내부 응답을 변환한 결과입니다. Worker 실패·차단·검사 제한은 정상으로 보정하지 않으며, 수집한 증거·한계와 함께 확인 불가를 반환할 수 있습니다. 클라이언트 취소는 현재 서버 작업 취소와 다릅니다.

## 관찰과 제한

`observer.cjs`, `dom-analyzer.cjs`, `network-analyzer.cjs`, `redirect-analyzer.cjs`가 수집을 담당합니다. DOM 검사는 open Shadow DOM을 고려합니다. 브라우저는 읽기 전용 방문을 수행하며 폼 자동 입력·제출, 로그인·결제, 다운로드를 수행하지 않습니다. 민감 필드가 있다는 사실만으로 정보 유출이나 피싱을 확정하지 않습니다.

컨테이너 내부 PNG와 작업은 임시 데이터입니다. API의 보고서·PNG·신고 집계도 단일 프로세스 메모리에 보관됩니다. 장기 보관·자동 만료·운영용 큐·사용자 인증은 구현하지 않았습니다.

Docker는 VM 수준의 격리를 보증하지 않습니다. 통제된 페이지에서 확인한 브라우저 실행·네트워크 제한을 임의의 악성 페이지에 대한 완전한 격리 보증으로 확대 해석하지 마세요. 외부 방문을 추가할 때는 리다이렉트와 하위 리소스, DNS 재해석·내부 주소 차단까지 실제 전송 경로에서 검증해야 합니다.

## Phishpedia 실험 파일

`Dockerfile.phishpedia`, `Dockerfile.phishpedia-model`, `PHISHPEDIA_REVISION`, `patches/`와 Python 스크립트는 실험용입니다. 외부 소스·모델 가중치·브랜드 자료·캐시는 저장소에 포함하지 않습니다. **현재 통합 실행에는 필요한 모델 가중치가 없고 Phishpedia의 브랜드 판정을 연결하지 않았습니다.** 이미지 빌드 이력이나 스크립트 존재를 모델 동작·성능 검증 완료로 해석하지 마세요. 모델 미검출·분석 실패는 정상 판정 근거가 아닙니다.

## 검증

`worker/tests/`의 분석 테스트, API의 Worker 계약·PNG·차단 회귀 검사, 실제 Docker의 통제된 페이지 PNG→API→프런트 연결을 구분해 확인합니다. 이번 로컬 통합에서는 실제 브라우저 촬영과 이미지 표시까지 확인했습니다. 실제 카메라·모바일 HTTPS·공개 Vercel 백엔드 연결·임의 악성 사이트 운영 검증은 포함하지 않습니다.
