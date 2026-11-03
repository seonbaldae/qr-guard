# QR Guard

QR 주소를 바로 열기 전에 검사하는 해커톤 서비스입니다. QR 촬영 또는 주소 입력 → 검사 → 화면 미리보기와 결과 확인 순서로 진행합니다.

[시연 페이지](https://qr-guard-five.vercel.app/)

프런트는 순수 JavaScript·Web Components, 백엔드는 FastAPI를 사용합니다. Google Safe Browsing, 격리 Chromium, Phishpedia로 주소와 페이지를 검사합니다.

## 로컬 실행

Python 3.11 이상, uv, Node.js, 실행 중인 Docker Desktop이 필요합니다. 서버 환경 변수 또는 저장소 루트 `.env`에 `GOOGLE_SAFE_BROWSING_API_KEY`를 설정합니다. 검사 URL은 Google에 전송됩니다.

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
.venv/bin/python scripts/run-local.py
```

[로컬 화면](http://127.0.0.1:8080/)과 [API 문서](http://127.0.0.1:8000/docs)를 엽니다. 기본 검사 대상은 Worker가 제공하는 `http://127.0.0.1:4000/demo/normal`입니다.

- `--skip-build`: 준비된 Docker 이미지를 재사용합니다.
- `--public-preview`: 공개 HTTP(S) 사이트의 로컬 검사를 허용합니다.
- `--port`, `--api-port`: 기본 포트 8080·8000을 변경합니다.

Ctrl+C로 종료합니다. 검사 결과·이미지·로컬 신고는 서버 메모리에 보관되며 재시작하면 초기화됩니다.

## 화면만 체험

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

[로컬 화면](http://127.0.0.1:8080/)의 **샘플로 확인하기**를 선택합니다. 정적 서버에서는 실제 검사 API가 동작하지 않습니다.

URL별 고정 판정 시연은 [url-verdict-demo.js](src/data/url-verdict-demo.js)의 `// enabled = true;`를 주석 해제해 켭니다. 실제 검사 없이 지정된 두 주소는 피싱, 나머지 유효한 주소는 비피싱 모의 결과로 표시합니다.

QR 촬영은 브라우저의 `BarcodeDetector` 지원이 필요합니다. 미지원 환경에서는 주소를 직접 입력하며, 휴대전화 카메라는 HTTPS 환경이 필요합니다.

## 배포

[vercel.json](vercel.json)에 따라 정적 프런트와 Python Functions를 함께 배포합니다. 클라우드 Worker·모델 설정과 배포 기록은 [클라우드 구성 문서](docs/cloud-preview.md)에 있습니다. 공개 서비스의 신고 기능은 준비 중입니다.

## 개발 참고

- [프런트 API](docs/frontend-api.md)
- [Worker 실행·설정](worker/README.md)
- [로컬 통합 검증 기록](docs/integration-verification.md)
- 프런트 테스트: [서비스](http://127.0.0.1:8080/tests/frontend/services.html), [화면](http://127.0.0.1:8080/tests/frontend/ui.html)

```sh
.venv/bin/python -m pytest -q
```

위협 미탐지는 안전 보장을 뜻하지 않습니다. 실제 휴대전화 촬영과 공개 모델 탐지 정확도는 별도 검증이 필요합니다.
