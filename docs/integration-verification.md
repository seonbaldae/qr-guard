# 실제 로컬 연동 검증

2026-10-31에 `scripts/run-local.py --skip-build --public-preview`로 실행했습니다.
프런트는 `http://127.0.0.1:8080`, API는 `127.0.0.1:8000`, Chromium은
`qr-guard-worker-live` 컨테이너 안에서 실행했습니다. 샘플 모드와 별도로 확인한 결과입니다.

| 실제 검사 | 확인 결과 |
| --- | --- |
| `https://example.com/` | Google 조회 완료·위협 미탐지, 실제 Chromium 방문·PNG 수신·모바일 결과 화면 표시 |
| `http://realistic-phishing-website.vercel.app/` | HTTPS 최종 주소 확인, 실제 PNG 93,905바이트 수신 |
| Google 공식 `testsafebrowsing.appspot.com/s/phishing.html` 테스트 주소 | 실제 위협 목록 일치, `malicious`, Worker 방문 건너뜀, 진입 버튼 없음 |
| 위 테스트 주소 신고 | 실제 접수 후 1건, 같은 검사에서 재전송해도 1건 유지, UI 신고 완료 표시 |
| `169.254.169.254` 메타데이터 목적지 | `target_not_allowed`, `blocked/unknown`, PNG 없음 |
| 컨테이너 직접 TCP 연결 | 공개·사설·메타데이터 주소 직접 연결 차단 확인 |

Docker는 비루트, 읽기 전용 파일 시스템, `network=none`, capabilities 제한,
프로젝트 seccomp, CPU·메모리·PID 제한으로 실행했습니다. 공개 사이트 통신은
별도의 호스트 TCP 중계기를 통해서만 이뤄지며 DNS의 모든 결과를 검사하고 검증한
공개 IPv4 주소에 연결합니다. TLS 인증서 검증은 Chromium이 수행합니다.

- Python 테스트: **387개 통과**(API 137개 포함). 테스트에서는 Google 응답을 대역 처리합니다.
- Worker 단위 테스트: Docker 안에서 **30개 통과**.
- 브라우저 서비스 테스트: **40개 통과**. UI 통합 테스트: **14개 통과**.
- 실제 결과 화면에 콘솔 경고·오류 없음. 정적 배포 출력 23개 파일 생성 확인.
- 서버 키가 Git 추적 파일 및 정적 출력에 포함되지 않음을 확인했습니다.

## 검증 한계

- 하드웨어 카메라와 휴대전화 HTTPS 촬영은 이번 검증에 포함하지 않았습니다.
- 모의 사칭 사이트는 Google에 등재되지 않았으며, 안내 화면에서 비밀번호 폼도
  관찰되지 않아 `no_known_threat`로 반환됐습니다. 이는 사칭 여부를 인증한 결과가 아닙니다.
- Phishpedia는 필요한 설정·가중치·브랜드 자료가 없어 초기화할 수 없으며 판정에 사용하지 않았습니다.
- IPv6 전용 사이트, CAPTCHA, 차단·시간·용량 제한 때문에 불완전한 방문은 보류할 수 있습니다.
- 신고 수는 현재 API 프로세스가 접수한 수입니다. 영속적인 전 세계 신고 수나 인증된 사용자별 집계가 아닙니다.
- 기존 Vercel 정적 배포에는 공개 HTTPS 백엔드를 배포·연결하지 않았습니다. 위 검증은 로컬 실행 결과입니다.
