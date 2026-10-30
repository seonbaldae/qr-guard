# Network analyzer completion

## Interface and integration

`const { createNetworkAnalyzer } = require('./network-analyzer.cjs')` creates an analyzer from a Playwright page and optional limits. Creation immediately attaches `request`, `response`, and `requestfailed` listeners; call before `page.goto`. The integrating owner must call `markPolicyBlocked(request)` only when its existing route policy aborts that exact Request. Do not infer a policy block from `requestfailed` or `ERR_ABORTED`.

`result()` returns exactly `{ requestHosts, requestCount, blockedRequestCount }`; hosts are sorted, deduplicated HTTP(S) hostnames, including blocked attempts. Request identity is deduplicated even when a failure or policy mark precedes `request`. `observations()` returns bounded copies of `{ host, method, statusCode, resourceType, outcome }` records, with outcomes `attempted`, `response_received`, `network_failed`, and `policy_blocked`. A response is not necessarily a successful HTTP status, and an attempt is not a connection. Policy-marked requests can also have a network-failed record. `limitations()` returns copies of truncation descriptions. `stop()` removes only these listeners, is idempotent, and freezes updates; snapshots are detached.

No URLs, paths, queries, fragments, credentials, headers, bodies, cookies, or error text are retained. Methods and resource types use allowlists; unknown values are null. Non-HTTP(S) and malformed URLs are ignored. This module does not touch routing, page state, or legacy evidence dispatch. Integration must disable overlapping legacy network listeners independently.

## Bounds and caveats

Defaults: `maxRequests=200`, `maxHosts=50`, `maxEvents=400`, `maxObservations=200`. Options must be positive integers: maxima respectively 10000, 10000, 20000, 10000. The event budget includes listener invocations and explicit policy marks, including duplicates and unsupported URLs. Once exhausted, later events and marks are ignored and a limitation is reported; counts and host lists can thus be incomplete. Request limit likewise bounds distinct tracked identities and blocks; host and observation caps independently omit excess metadata, with limitations. Counts are bounded observations, not a complete traffic census. Captured hostnames themselves are potentially sensitive metadata.

## Verification

Test-first: the initial request-host test failed with `MODULE_NOT_FOUND` before the module was created; it passed after the initial implementation. Expanded tests failed against the initial implementation, then passed after implementing the remaining contract.

`node --test worker/tests/network-analyzer.test.cjs`: **5 tests, 5 passed, 0 failed**. Tests use EventEmitter stubs only. No live browser, Docker, egress isolation, integration, or end-to-end test was performed; no external visits or downloads occurred.
