# QR Guard v0.3 — Network / Redirect / DOM·Form 통합 완료 보고

## 범위와 소유권

- 기존 Network·Redirect 두 전담 작업을 보존하고, 사용자 추가 지시에 따라 DOM/Form 전담 에이전트 1개를 추가했다. 총 3개 전담 작업의 산출물을 메인 에이전트가 순차 통합했다.
- Network·Redirect 모듈과 독립 테스트는 원래 에이전트 산출물과 바이트 단위로 동일함을 확인했다. 원본 worktree 산출물은 수정하지 않았다.
- DOM/Form은 신규 `dom-analyzer.cjs`에 구현했다. 통합 중 발견한 빈 action 처리 오류와 비교 사실의 목적지 호스트 식별을 실제 저장소 사본에서 보완했다.
- 브랜드 로고 자동 식별, 공식 브랜드 도메인 매핑, Phishpedia, FastAPI 연결, 최종 악성 판정은 구현하지 않았다. 팀원 소유 파일은 변경하지 않았다.
- 커밋·푸시·PR·병합은 수행하지 않았다.

## 작업별 변경 파일과 결과

| 작업 | 모듈 / 테스트 / 전담 보고서 | 검증 |
|---|---|---|
| Network | `worker/network-analyzer.cjs`, `worker/tests/network-analyzer.test.cjs`, `worker/reports/network-completion.md` | 독립 테스트 5개, 실제 Chromium N1 통과 |
| Redirect | `worker/redirect-analyzer.cjs`, `worker/tests/redirect-analyzer.test.cjs`, `worker/reports/redirect-completion.md` | 독립 테스트 11개, 실제 Chromium R1·R2 통과 |
| DOM/Form | `worker/dom-analyzer.cjs`, `worker/tests/dom-analyzer.test.cjs`, `worker/reports/dom-completion.md` | 독립·회귀 테스트 6개, 실제 Chromium DOM 시나리오 3개 통과 |
| 공통 연결 | `worker/worker.cjs`, `worker/observer.cjs`, `worker/tests/worker-analysis.test.cjs`, `worker/tests/observer-analysis.test.cjs` | Worker VM 회귀 5개 + observer 보호 회귀 1개 통과 |
| 패키징·브라우저 검증 | `worker/Dockerfile.worker`, `worker/package.json`, `worker/package-lock.json`, `worker/tests/browser-analysis.cjs`, `worker/tests/run-browser-review.py` | Worker 이미지 빌드 및 실제 jobs API 검증 통과 |

단위·VM 테스트 **28개**, 실제 Docker/Chromium 테스트 **7개**, 합계 **35개 통과**, 최종 실패 **0개**. Mock 기반 테스트와 실제 브라우저 검증은 별도 실행했다.

## 통합 동작

1. 최초 `page.goto` 전에 Network·Redirect 이벤트를 등록한다.
2. 기존 observer의 request/response 수집만 옵션으로 끄고, 다운로드 취소·팝업 닫기·증거/신호 ID·100개 증거 상한은 재사용한다. 기존 `collectDom()`은 유지하지만 새 Worker 경로에서는 호출하지 않는다.
3. 최초 load 후 PNG를 임시 파일에서 원자적으로 확정하고 `screenshotStatus=ready`로 공개한다. 이후 기존 짧은 관찰 구간과 DOM/Form 분석을 수행한다.
4. `networkAnalysis`, `redirectAnalysis`, `domAnalysis`를 최종 jobs JSON에 추가한다. 불완전한 DOM 관찰로 부재를 확정할 수 없으면 `domAnalysis=null`과 limitations를 반환한다.
5. 실제 정책의 `route.abort()` 성공 후에만 두 이벤트 분석기에 정책 차단 근거를 전달한다. 일반 requestfailed는 정책 차단으로 계산하지 않는다.
6. 종료 전에 자기 리스너를 해제한다. 최종 URL은 실제 메인 프레임 commit 기반이며 차단된 목적지는 finalUrl로 승격하지 않는다. 이미 준비된 PNG는 뒤늦은 분석 오류로 취소하지 않는다.
7. 예외 메시지 원문 대신 고정 오류 분류를 로그로 남겨 URL·토큰을 포함할 수 있는 브라우저 예외 문자열을 저장하지 않는다.

## 실제 검증

- **DOM 1:** JS가 뒤늦게 생성한 로그인 폼, Open Shadow DOM, OTP·결제카드 autocomplete, 동일 출처 iframe과 통제된 cross-origin iframe. 실제 password 입력 4개, 접근 가능한 프레임 3개 관찰. input.value getter 호출 0회. 폼 action의 query·입력값 sentinel 미저장. 제출 요청 없음.
- **DOM 2:** 외부 `<base>`가 있어도 비어 있는 form action은 document URL을 목적지로 해석. Chromium의 실제 `form.action`과 일치.
- **DOM 3:** 실제로 분리된 iframe의 평가 실패를 관찰하여, 확인할 수 없는 비밀번호 필드 수를 0으로 확정하지 않고 null 및 limitations 반환.
- **N1:** 허용된 로컬 문서·이미지 응답, 실제 연결 실패, 정책으로 차단한 요청을 구분. 차단 수는 실제 정책 차단 1건만 반영.
- **R1:** 실제 HTTP 302 → 307 → 최종 문서. 최종 commit과 HTTP 체인 2개 확인.
- **R2:** 실제 JS 페이지 이동 후 외부 `.test` 목적지 시도는 route 정책으로 차단. 마지막 실제 로컬 이동만 finalUrl에 남기고 외부 목적지는 blocked 시도로만 기록. 외부 사이트는 방문하지 않음.
- **Worker jobs / F4:** 실제 `POST /internal/jobs` 202 → status running 중 PNG 200 → completed → PNG 200. 재요청 200, busy 429, 비허용 URL 422, 이전 `/internal/analyze` 404 유지. 증거 ID 중복과 dangling signal evidenceIds 없음.
- PNG를 실제 pixel decode해 **390×844** 확인. 단색/빈 화면이 아니며 이미지 직접 확인에서도 정상 데모 문구가 렌더링돼 있다.
- 단위·VM 테스트에서는 캡처 실패 후 관찰 결과 유지, DOM 분석 중 PNG 조회, 뒤늦은 DOM 실패 후 ready PNG 유지, 실제 정책 콜백 연결, HTTP/blob/data 다운로드 취소 유지도 확인했다. 분석 실패 후 PNG 유지 검증은 VM 테스트이며 실제 컨테이너 timeout-after-PNG 검증으로 부풀려 설명하지 않는다.

## 격리와 패키징

- Worker의 허용 URL은 그대로 `http://127.0.0.1:4000/demo/normal` 하나다. 고급 시나리오는 별도의 테스트 컨텍스트와 통제된 로컬 HTTP fixture에서 검증했으며 Worker의 URL 허용 목록은 확대하지 않았다.
- 테스트 컨테이너의 `network=none`, 비루트 `pwuser`, read-only root, no-new-privileges, 기존 seccomp와의 JSON 일치, cap-drop ALL + 기존 검토 프로필의 SYS_CHROOT만 유지, pids 256, memory 1 GiB를 실제 inspect로 확인했다. Chromium sandbox를 켰고 프로젝트 보안 파일은 수정하지 않았다.
- 컨테이너에 읽기 전용 테스트 소스만 마운트했다. 생성된 PNG/JSON은 컨테이너 tmpfs에서 stdout artifact 채널로 반환해 호스트에서 저장했다. 파일 권한·소유권을 완화하지 않았다.
- `tldts@7.4.19`를 package.json과 lockfile에 고정하고 Worker 이미지가 비루트 전용 경로에서 npm ci 하도록 했다. Playwright는 기존 브라우저 기반 이미지의 설치를 사용한다.
- 실제 검증 이미지: `qr-guard-review-worker:analysis-v03`. 테스트 빌드에서는 로컬에 이미 검증된 `qr-guard-review-browser:db310f0`를 FROM 입력으로 사용했다. 소스 Dockerfile의 `FROM seonbaldae-browser`는 유지했다.

## 발견·수정한 실패

- 외부 `<base>` + 빈 action: DOM 분석기가 base host를 잘못 반환했다. 실제 브라우저 및 단위 회귀로 RED를 확인한 뒤 document.URL을 사용하도록 수정했다.
- 다운로드 메타데이터: data/blob URL을 다시 URL로 변환하던 통합 코드가 예외를 내면 취소가 실행되지 않을 수 있었다. 프로토콜 확인과 안전한 host 추출을 분리하고 세 유형의 취소 회귀를 통과시켰다. 실제 다운로드를 수행한 테스트가 아니라 이벤트 더블 기반 보호 검증이다.
- 테스트 출력 권한: 컨테이너 pwuser의 UID가 호스트와 달라 host bind 출력 쓰기가 실패했다. 권한 변경 없이 tmpfs/stdout artifact 방식으로 바꿨다.
- 테스트 subprocess 종료: 실패 경로의 무한 종료 대기가 원래 오류를 가렸다. 소유한 Worker 자식 프로세스에 한해 제한된 종료 대기와 강제 종료 fallback을 추가했다.
- 서브에이전트 B의 보고상 모든 행동별 엄격한 RED→GREEN 순서가 지켜진 것은 아니다. 기존 산출물을 보존하고 독립 테스트 재실행 및 실제 브라우저 검증을 추가했다. 완전한 TDD 준수로 주장하지 않는다.

## 통합 시 주의점 / 남은 한계

- 공식 도메인 비교에는 **검증된 registered domain**과 PSL-aware resolver를 명시적으로 주입해야 한다. 현재 Worker에는 팀원 매핑을 임의 연결하지 않아 해당 비교는 limitations에 unknown으로 남는다. 실제 DOM fixture에서는 통제된 값과 tldts를 주입해 mismatch 관찰을 검증했다. 폼 목적지 관찰은 실제 제출·유출의 증거가 아니다.
- iframe은 Playwright가 이미 로드된 프레임에서 읽을 수 있는 범위만 관찰한다. 실제 cross-origin 프레임을 읽었다고 모든 iframe 접근 가능성을 보장하지 않는다. closed Shadow DOM·분리된 프레임·저장/순회 상한은 limitations로 명시한다. 일부만 관찰해 양수 필드 개수가 나오면 전체 수가 아닌 관찰된 하한이다.
- DOM은 시점 기반 스냅샷이고 대화형 입력·클릭·제출은 수행하지 않는다. 이후 페이지 변화의 부재나 안전을 보증하지 않는다.
- URL 인증정보·query·hash는 제거한다. URL path와 page title의 임의 민감 문자열 탐지는 휴리스틱이므로 모든 비정형 개인정보 제거를 보장하지 않는다. 입력값·쿠키·인증 헤더·요청 본문은 수집하지 않는다.
- Network의 개수는 설정 상한 안에서 관찰한 수다. 이벤트·요청·호스트·메타데이터 상한이 적용되면 limitations를 반드시 함께 해석한다.
- FastAPI와 C jobs API 연결, verified brand mapping, 최종 위협 상관분석은 여전히 별도 작업이다. 이 결과를 서비스 전체 통합/배포 성공이나 안전 판정으로 해석하지 않는다.

## 재실행과 결과 파일

저장소 루트 기준:

- `npm --prefix worker ci --ignore-scripts --no-audit --no-fund` 후 `npm --prefix worker test`.
- 이번 호스트 검증은 이미 준비된 별도 의존성 경로를 사용해 `NODE_PATH=/srv/project/hackathon/.worker-review/node/node_modules npm --prefix worker test`로 실행했다.
- 위 검증 태그로 이미지를 빌드한 뒤 `python worker/tests/run-browser-review.py`. 이 runner는 격리 설정 readback과 소유한 테스트 컨테이너 정리를 포함하며, 기존 서비스는 변경하지 않는다.
- 생성된 결과: `/srv/project/hackathon/.worker-review/analysis-v03/{verification-summary.json,browser-results.json,normal-job.json,normal.png,unit-test-output.txt,browser-test-output.txt}`.
