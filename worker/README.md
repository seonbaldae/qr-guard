# Docker Worker 개발 진행본

기존 app과 분리된 브라우저 Worker 및 Phishpedia 분석 환경입니다.

## 구성
- Dockerfile: seonbaldae-browser 기본 이미지
- Dockerfile.worker: 브라우저 Worker
- worker.cjs / observer.cjs: 작업 처리 및 페이지 관찰
- browser.cjs: 기본 브라우저 실행 코드
- seccomp_profile.json: 브라우저 실행용 보안 프로필
- Dockerfile.phishpedia: Phishpedia 기본 분석 환경
- Dockerfile.phishpedia-model: 라이브러리·모델 설치
- PHISHPEDIA_REVISION: 사용한 외부 소스 커밋
- patches/: 로컬에 보관된 Phishpedia 수정 변경분

## 브라우저 이미지 빌드
이 디렉터리에서 실행합니다.

    docker build -t seonbaldae-browser .
    docker build -f Dockerfile.worker -t seonbaldae-worker .

컨테이너 실행에는 별도의 네트워크 및 보안 설정이 필요합니다.

## 로컬 데모 URL 검사

Worker가 실행 중일 때 저장소의 `worker` 디렉터리에서 실행합니다.

    docker build -f Dockerfile.worker -t seonbaldae-worker:test .
    docker run --rm -d --name seonbaldae-worker-test \
      -p 127.0.0.1:4001:4000 \
      --security-opt seccomp=seccomp_profile.json \
      --pids-limit 256 --memory 1g --shm-size 256m \
      seonbaldae-worker:test

    WORKER_BASE=http://127.0.0.1:4001 node scan.cjs http://127.0.0.1:4000/demo/normal
    WORKER_BASE=http://127.0.0.1:4001 node scan.cjs http://127.0.0.1:4000/demo/suspicious
    WORKER_BASE=http://127.0.0.1:4001 node scan.cjs http://127.0.0.1:4000/demo/redirect

원하는 공개 URL도 같은 방식으로 마지막 인자에 넣습니다.

    WORKER_BASE=http://127.0.0.1:4001 node scan.cjs https://example.com/

`suspicious`는 폼과 비밀번호 필드 탐지 확인용이며 실제 피싱 페이지가 아닙니다.
`redirect`는 `suspicious`로 이동해 최종 URL과 리디렉션 관찰을 확인합니다.
`WORKER_BASE`는 호스트에서 접근하는 Worker API 주소입니다. 검사 URL의 4000 포트는
컨테이너 내부에서 브라우저가 방문하는 주소이므로 그대로 둡니다.

공개 URL은 최초 요청과 리디렉션·하위 리소스마다 DNS 결과를 확인합니다. localhost,
사설망, link-local, 메타데이터 주소, 비표준 포트, 인증정보가 포함된 URL은 차단합니다.
운영 환경에서는 DNS 검사 외에도 egress 프록시나 방화벽으로 같은 정책을 강제해야 합니다.

## Phishpedia
외부 소스, 모델 가중치, 브랜드 자료와 캐시는 Git에 포함하지 않습니다.
Dockerfile.phishpedia 빌드 전 third_party/Phishpedia 소스를 준비해야 합니다.
사용한 소스 버전은 PHISHPEDIA_REVISION에 기록합니다.

현재 개발 환경은 ARM Mac에서 linux/amd64 에뮬레이션을 사용합니다.

## 검증 상태
- Worker 작업 처리 및 PNG 반환: 로컬 테스트 확인
- Phishpedia 환경·모델 이미지 빌드: 확인
- Phishpedia 실제 분석: 오류 수정 후 재검증 필요
- patches의 수정 내용을 이미지에 적용하는 자동화: 미완료
- API 서버와 최종 판정 통합: 미완료

브랜드 미검출 또는 분석 실패를 정상 판정으로 사용하지 않습니다.
