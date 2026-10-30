# Redirect analyzer completion

## Interface
`createRedirectAnalyzer(page, { initialUrl, maxEntries = 50, maxEvents = 400, resolveRegisteredDomain } = {})` attaches its request, response and main-frame navigation listeners immediately. Call `markPolicyBlocked(request)` only for an actual policy abort; call `stop()` when finished. `result()` returns the v0.3 redirect shape; `observations()` returns bounded attempt, HTTP redirect and commit records with host/domain-change metadata; `limitations()` describes truncation. Snapshots are copies. Registered-domain extraction defaults to `tldts.getDomain(host, { allowPrivateDomains: true })`; the integration owner must pin and install `tldts@7.4.19` in the actual worker. IP and localhost domain comparison is unknown.

No route policy, shared code or brand comparison was changed. Initial normal commit is not a redirect; requests and HTTP responses alone do not set `redirected`. The final URL comes only from observed valid HTTP(S) main-frame commits. URL evidence strips credentials, query and fragment and heuristically redacts token-like path segments. Query-only changes are detected with keyed fingerprints. Redaction is heuristic and cannot guarantee identification of all secrets embedded in arbitrary paths; consider host-only evidence if this is unacceptable.

## Verification
`NODE_PATH=/srv/project/hackathon/.worker-review/node/node_modules node --test worker/tests/redirect-analyzer.test.cjs` passed 11/11 tests. Installed test dependency reports 7.4.19. Tests use EventEmitter Playwright-like mocks, not Chromium or Docker. They cover multihop and relative HTTP redirects, client commits, blocked ordering and deduplication, uncommitted/failed requests, subframes/304/non-HTTP, PSL/private suffixes, redaction, query-only changes, bounds, defensive copies, and listener cleanup.

The initial test and the R1 slice were observed failing before their implementations; two later regressions were observed failing before fixes. Several additional coverage tests passed immediately after the broader R1 implementation, so the requested strict per-behavior RED→GREEN discipline was not achieved for every behavior.

## Limitations
Events beyond observation and chain caps are omitted; HTTP/client attribution relies on observable event ordering and bounded retained edges, not JavaScript mechanism detection. Redirection and domain metadata are observations, not a verdict. An absent commit remains unknown, not a completed visit. No real browser, container, integration, policy or egress test was run. No shared files were integrated.
