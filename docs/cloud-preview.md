# 요청별 클라우드 Worker 미리보기

## 현재 상태

2026-10-31 기준으로 클라우드 관찰 코드·전용 Docker 이미지와 공개 API 연결을 준비하고 있습니다.
**최종 이미지의 Chromium 실행과 공개 HTTPS 요청에서 PNG를 받는 검증은 아직 완료되지 않았습니다.**
이 문서를 실제 클라우드 미리보기 배포 성공으로 해석하지 않습니다.

기존 공개 주소의 정적 API 배포·Google 실제 조회·판단 보류 검증 이력은
[공개 배포 기록](public-deployment.md)에 유지합니다. 기존 로컬 Docker·Phishpedia 경로는
별도로 보존하며 클라우드용 이미지가 해당 모델을 포함한다고 가정하지 않습니다.

## 실행 구조

1. 사용자 브라우저는 같은 출처의 `POST /api/analyze`에 URL을 보냅니다.
2. API가 정적 검사를 수행하고 알려진 위협이면 방문을 생략할 수 있습니다.
3. 클라우드 활성화 시 고정된 VCR 이미지로 일회성 Vercel Sandbox VM을 만듭니다.
4. API가 강제한 VM 네트워크 정책과 IPv6 비활성화를 확인한 뒤 입력 파일을 전달합니다.
5. 비루트 `node /app/cloud/run.cjs`가 Chromium 샌드박스를 유지해 페이지를 읽기 전용으로 관찰합니다.
6. API가 같은 검사 ID의 결과 JSON·PNG를 검증하고 VM을 정리합니다.
7. 프런트는 `previewImage`의 PNG bytes를 Blob 이미지로 표시합니다. 원본 HTML·JS는 사용자 기기에서 실행하지 않습니다.

Docker 이미지를 임시 VM의 실행 파일 시스템으로 사용하는 방식입니다. 사용자 Mac의 Docker
데몬을 공개하거나 Vercel 함수에 Docker 소켓을 연결하지 않습니다. 이미지의 ENTRYPOINT/CMD가
자동으로 실행될 것이라고 가정하지 않고 runner를 명시적으로 호출합니다.

## 이미지 준비와 재배포

### 1. 클라우드 전용 이미지 빌드

저장소 루트에서 빌드 컨텍스트를 `worker/`로 지정합니다.

```sh
docker build --platform linux/amd64 \
  -f worker/cloud/Dockerfile \
  -t qr-guard-cloud:review \
  worker
```

현재 Dockerfile은 `node:24-bookworm-slim`과 고정 Playwright `1.64.1`·tldts `7.4.19`를
사용하며 Chromium headless shell과 시스템 의존성을 설치합니다. `procps`의 `sysctl`은
VM의 IPv6 설정과 확인에 필요합니다. 실행 사용자는 UID 1000의 `node`입니다.
브라우저·Node 모듈은 비루트 사용자가 읽을 수 있어야 합니다.

`worker/cloud/Dockerfile.dockerignore`는 이 빌드에만 적용합니다. 기존 팀 Dockerfile은
변경하지 않으며 모델·캐시·URL 입력·촬영 파일·API 키를 이미지에 넣지 않습니다.
프런트에는 라이브러리·번들러를 추가하지 않습니다.

### 2. VCR에서 변경 불가능한 이미지 참조 확정

인증된 배포 도구에서 기존 팀·프로젝트를 확인하고 이미지를 VCR에 빌드 또는 업로드합니다.
빌드가 성공한 후 해당 이미지의 `@sha256:` 참조를 확인합니다. 가변 tag나 빌드 작업 생성만으로
런타임 준비 완료를 선언하지 않습니다. 같은 tag를 다시 빌드했더라도 실행 중인 고정 digest를
자동으로 바꾸지 않습니다.

이 문서 작성 시 `cloud-20261031-2` 이미지 빌드가 진행 중입니다. 최종 digest·이미지 실행·공개
API 검증 결과는 실제 완료 후 별도로 기록해야 합니다.

### 3. 검증 게이트를 통과한 후 서버 설정

서버 전용 설정은 다음 두 가지입니다. 실제 이미지 참조와 키는 문서나 프런트에 넣지 않습니다.

```text
QR_GUARD_CLOUD_WORKER_IMAGE=<VCR의 고정 @sha256 참조>
QR_GUARD_CLOUD_WORKER_VERIFIED=false
```

실제 이미지 VM에서 아래 사항을 확인한 뒤에만 `QR_GUARD_CLOUD_WORKER_VERIFIED=true`를
설정합니다. 플래그는 검증 결과에 대한 운영 설정이며 방화벽 구현을 대신하지 않습니다.

- API가 요구하는 사설망·링크 로컬·메타데이터 차단 정책이 VM에 적용됐습니다.
- VM의 모든 IPv6 인터페이스가 비활성화됐으며 실제 상태를 읽어 확인했습니다.
- 비루트 Chromium이 `chromiumSandbox: true`로 실행됩니다.
- 실제 페이지의 결과 JSON과 정상 PNG를 회수하고 동일 검사 ID를 확인했습니다.
- 성공·실패 경로에서 VM이 정리되며 공개 API·프런트까지 이미지가 연결됩니다.

Google 키·Vercel SDK 자격 증명·OIDC 토큰은 API 서버에만 둡니다. VM 환경 변수나 이미지로
전달하지 않습니다. 요청 URL은 임시 입력 JSON에 전달하며 명령 인자·로그에 넣지 않습니다.

### 4. 프런트·Python API 배포

```sh
node scripts/prepare-vercel.mjs --public --cloud-preview
```

이 명령은 생성된 정적 설정을 `direct/sandbox`로 바꿉니다. API는 `app/public_api.py`와
`app/cloud_worker.py`를 사용하고 네이티브 `api/*.py` Functions로 배포합니다.
로컬 개발 기본 `job/sandbox`와 기존 `worker.cjs` 작업 서버는 바꾸지 않습니다.

현재 제한은 프런트 전체 요청 90초, Vercel Function 120초, runner 관찰 기본 20초입니다.
이미지 부팅·SDK 호출·결과 회수·정리 시간도 전체 요청 제한 안에 포함됩니다.
클라이언트 취소를 서버 VM 정리 완료로 설명하지 않습니다.

### 5. 공개 주소에서 실제 응답 확인

배포 준비 완료 후 `GET /api/health`·`GET /api/capabilities`와 실제 `POST /api/analyze`를
확인합니다. 설정상 활성화와 특정 요청의 성공은 다릅니다. 실제 응답의 `sandboxAnalysis`,
최종 URL, 촬영 상태·검사 ID와 `previewImage`가 일치하는지 확인해야 합니다.

이미지는 390×844 PNG이며 1.5MiB 상한을 적용합니다. 서버는 이미지 형식·실제 디코딩·픽셀
수를 검사하고 프런트는 검사 ID·MIME·시그니처·용량을 다시 검사해 Blob으로 표시합니다.
실패·정책 차단·DOM 누락은 정상이나 0개 필드로 보정하지 않습니다. PNG가 이미 있다면
부분 결과로 보존할 수 있지만 검사 완료·안전 판정과 분리합니다.

## 지금까지의 제한된 검증

root의 관리형 VM 검사에서 공개 목적지 요청의 200 응답, 메타데이터 목적지의 `EHOSTUNREACH`,
사설 목적지의 `ECONNRESET`, IPv6의 `EADDRNOTAVAIL`을 확인했습니다. 이는 기본 VM의
egress 검사 결과이며 **새 최종 이미지의 Chromium 실행·PNG·공개 서비스 연결 검증을 대신하지 않습니다.**

관찰 runner의 정책·부분 결과 단위 검증과 실제 이미지 실행은 구분합니다. 현재 최종 이미지 빌드와
공개 통합 검증이 진행 중이므로 실행하지 않은 검증을 통과했다고 쓰지 않습니다.

## 판정과 남은 범위

클라우드 경로는 초기 로딩 후 짧은 관찰을 수행하고 DOM·네트워크·페이지 이동 메타데이터를
수집합니다. 폼을 클릭하거나 실제 계정·카드·OTP 정보를 입력·전송하지 않습니다.

**공개 클라우드 이미지에는 Phishpedia가 연결되지 않았습니다.** 화면 촬영이 성공해도 브랜드
사칭 여부가 미확인이면 `unknown`을 유지합니다. Google 목록 미일치만으로 정상 접속을
허용하지 않습니다. 알려진 위협 탐지 근거와 촬영 성공을 구분하며, 스크린샷만으로 공식
운영 주체를 인증하지 않습니다.

신고 공유 저장소도 아직 연결하지 않아 `reportAvailable: false`와 신고 건수 `null`을 유지합니다.
로컬 프로세스의 메모리 집계나 URL별 고정 데모 결과를 공개 실측 데이터로 사용하지 않습니다.
