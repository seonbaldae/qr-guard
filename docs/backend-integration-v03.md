# Backend integration v0.3

## Scope / status

Implemented on the local `feat/connect-front-api` checkout. The frontend team's files are unchanged. No Git commit, push, merge or deployment is performed by this implementation.

- A public endpoints remain `POST /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/screenshot`.
- A now calls C `POST /internal/jobs`, polls `GET /internal/jobs/{id}`, and independently fetches PNG from `GET /internal/jobs/{id}/screenshot`. There is no fallback to `/internal/analyze`.
- A publishes a validated PNG while report status is running and verdict is null. Later C/poll/model failures retain a previously valid PNG.
- The pure `app/correlation.py` consumes typed observations. Worker `block/warn/allow` is never mapped directly into public verdicts.
- `app/brand.py` invokes the teammate's original `analyze-brand.py` in an offline container through `app/brand_runner.py`. Existing Network, Redirect, DOM and Phishpedia analyzer files are unchanged.
- The teammate's GSB Protobuf fix and its tests were incorporated as source, without Git history operations, from commit `3b5e735e4eaa856c5820e929711894b0d392f6c4` (`fix/safebrowsing-protobuf`). The original tests remain unchanged; the decoder additionally rejects incorrect wire types on known response fields so malformed provider data cannot become a clean lookup.

## Decision rules

1. A verified Google Safe Browsing positive, with actual linked evidence, has highest priority (`malicious`). A known malicious initial URL skips C entirely. A final committed destination is looked up separately; a blocked destination is never queried as a visited final URL.
2. Reliable Phishpedia identity + verified official registered-domain mismatch + rendered password/OTP field => `suspicious`. Reliable means the runner's actual model threshold is met, model/reference provenance is present, the same scanId and actual final URL match, the model's domain comparison agrees with an offline PSL-based normalization, and linked evidence exists. User `expectedBrand` or raw logo similarity alone does not establish automatic identity.
3. External form action hosts, actual redirect observations and overlapping network request hosts supplement that combination. A request attempt is not proof of a successful submission or exfiltration. CDN requests, ordinary redirects and password fields alone are never suspicious.
4. `no_known_threat` requires completed necessary checks: in sandbox mode both initial/final Google checks, a validated PNG, DOM/Network/Redirect observations, trustworthy brand/domain comparison, no policy blocks or incomplete observations, and real evidence links. Static-only mode remains explicitly limited to static coverage.
5. Missing, failed, unidentified, blocked or incomplete required observations produce `unknown`, unless independently verified positive evidence supports a stronger finding. A model unavailable result cannot become a clean scan.

`reasons`, deduplicated actual `evidenceIds`, and `limitations` accompany the verdict. C's raw evidence/error text is not copied into public reports: bounded public evidence is rebuilt from typed observed metadata. Page title and URL redaction are heuristic and do not guarantee detection of arbitrary sensitive prose/path strings.

## Runtime configuration

Use the existing Python requirements and one Uvicorn worker. Set configuration in the server environment, not tracked secrets files:

- `QR_GUARD_WORKER_URL`: internal C origin, e.g. `http://127.0.0.1:4000` on an explicitly isolated authorized deployment.
- `QR_GUARD_DEMO_ORIGINS`: comma-separated exact permitted demo origins.
- `QR_GUARD_WORKER_EGRESS_VERIFIED=true`: only after actual egress validation; an application allowlist is not proof of isolation. Default is blocked.
- `QR_GUARD_WORKER_TIMEOUT_MS`: 1000..30000, default 20000.
- `QR_GUARD_WORKER_POLL_INTERVAL_MS`: positive, default 100.
- `QR_GUARD_BRAND_WORKER_DIRECTORY`: absolute directory containing the teammate's `analyze-brand.py`, `run-phishpedia.py`, `.cache/LOGO_FEATS.npy` and `.cache/LOGO_FILES.npy`. Only operator-trusted model/catalog artifacts may be used.
- `QR_GUARD_BRAND_IMAGE`: already installed offline model image, default `seonbaldae-phishpedia`. It is resolved to an immutable local image ID before launch; this connector does not pull/download models.
- `QR_GUARD_BRAND_TIMEOUT_MS`: positive model execution deadline, default 180000.
- `GOOGLE_SAFE_BROWSING_API_KEY`: server-only existing GSB configuration. No key is stored by this change.

Run the API using `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1`. Deployment/network enablement is not performed here. The frontend's live transport still has its own 30-second overall timeout; real Phishpedia can take longer. Do not silently shorten model execution or claim a successful frontend E2E from backend-only tests.

Brand runs with `--network none`, read-only root, cap-drop ALL, no-new-privileges, resource limits and read-only source/input mounts. It uses the API process's nonroot UID/GID to read its private input and calls the installed `/opt/phishpedia/.pixi/envs/default/bin/python` directly; the image's root-private `pixi` executable is not required. Generated input lives under workspace `.backend-runtime` in an automatically cleaned per-job directory; output is returned over a bounded stdout channel, not shared arbitrary output files. The runner hashes actual installed domain-map/features and reads the model's actual similarity threshold; no invented risk weights or confidence thresholds are introduced. Model errors and missing provenance remain unknown.

An initial PNG is not evidence of the content of a later client-navigation destination. If URL binding changes or client navigation makes binding uncertain, the PNG remains available but is not used for brand/domain correlation. Uniform/blank PNGs trigger an explicit visual-inspection limitation rather than being treated as verified visual coverage; nonuniform loading screens are not comprehensively detected.

The adapter retains a validated full incoming destination only as a transient Pydantic private attribute for Google lookup and PNG binding; public models, evidence and logs never receive that attribute. Query-only or redacted-path-only differences must not be compared through their public sanitized URLs. The current C contract itself already removes queries/path secrets; A cannot reconstruct removed information. A redirected destination supplied only in this redacted form produces an explicit final-URL coverage limitation and is not used to establish reliable PNG/brand binding or a clean result. Missing redirect metadata or an unexplained destination change likewise prevents PNG/model binding. A full incoming destination, when actually supplied by a compatible trusted transport, is checked before redaction rather than silently downgraded to a path-only Google lookup.

## Verification levels

- Full Python suite: **376 passed** at final verification, including original precheck/API regression tests, migrated v0.3 jobs mocks, correlation cases, GSB Protobuf decoder and invalid-wire-type cases, private-destination reviewer regressions, privacy/bounds/timeout tests and PNG pixel decoding.
- `PYTHONPATH=. python tests/run_backend_review.py`: real ephemeral FastAPI HTTP server -> Unix-domain HTTP transport -> actual jobs HTTP server in a network-none review container -> actual sandboxed Chromium normal fixture -> running public PNG 200 -> terminal report. No container TCP ports are published and no external site is visited. Test-only read-only tldts dependency mount allows the container to run under the host's nonroot UID without changing installed-image ownership.
- The default regression mode uses an explicitly injected Google no-match test double and leaves brand inference disabled. Run **`PYTHONPATH=. python tests/run_backend_review.py --live`** for the separately verified real integration: actual Google Safe Browsing v5, actual Docker/Chromium and actual installed Phishpedia inference, without provider/model test doubles.
- Existing frontend service tests can be run separately without changing frontend files. Their response fixtures are not proof of actual model/provider execution.

Real outputs: `/srv/project/hackathon/.worker-review/backend-v03/{summary.json,report.json,running-report.json,preview.png}`.

## Actual provider/model integration result

The operator installed `seonbaldae-phishpedia` and matching 2,996-entry `.cache/LOGO_*` arrays. Actual inference on the real Worker PNG completed with `brand_unidentified`, highest observed similarity about 0.752 versus the actual model threshold 0.87. Public `logoAnalysis.status=unknown` correctly distinguishes a completed-but-unidentified model from an unavailable runtime. The unbranded normal demo's final verdict is `unknown`, not an invented clean finding.

The actual public API also returned `malicious` for Google's official reputation-test URL and skipped C entirely. The reputation query did not visit that webpage. Separately, the teammate's installed-reference recognition/production hostname comparison check recognized PayPal and passed seven domain cases. This reference check is not screenshot logo-detector accuracy validation or a phishing-site browser visit.

Actual artifacts are under `/srv/project/hackathon/.worker-review/live-backend/`: `verification.json`, `summary.json`, `report.json`, `running-report.json`, `preview.png`, `known-threat-report.json`, `model-probe.json`, `brand-reference-check.json`. Review processes and owned containers were stopped after verification; this is real integration testing, not a deployment or persistent service configuration change. Broad brand accuracy, a branded controlled browser D1 fixture outside C's current exact-URL allowlist, full final-query provenance after redirection, and production deployment remain distinct unverified scopes.

The preexisting frontend reporting endpoint remains unimplemented; it is not part of the three contracted scan APIs or this correlation task. Do not present a successful report submission when the server returns 404.
