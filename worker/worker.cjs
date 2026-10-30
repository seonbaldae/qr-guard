const http = require("node:http");
const fs = require("node:fs/promises");
const { chromium } = require("playwright");
const { createObserver } = require("./observer.cjs");
const { createNetworkAnalyzer } = require("./network-analyzer.cjs");
const { createRedirectAnalyzer } = require("./redirect-analyzer.cjs");
const { createDomAnalyzer } = require("./dom-analyzer.cjs");

const jobs = new Map();
const TEST_URL = "http://127.0.0.1:4000/demo/normal";
let busy = false;

function json(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

function error(res, status, code, message) {
  json(res, status, { error: { code, message } });
}

async function readBody(req) {
  let text = "";

  for await (const chunk of req) {
    text += chunk;
    if (text.length > 4096) {
      throw new Error("요청이 너무 큽니다.");
    }
  }

  return JSON.parse(text);
}

async function runJob(job) {
  let browser;
  let observer;
  let network;
  let redirect;
  let dom;
  let expired = false;

  job.status = "running";
  job.screenshotStatus = "pending";

  const timer = setTimeout(() => {
    expired = true;
    if (browser) void browser.close().catch(() => {});
  }, job.timeoutMs);

  try {
    browser = await chromium.launch({
      headless: true,
      chromiumSandbox: true,
      timeout: 10000,
    });

    if (expired) throw new Error("timeout");

    const context = await browser.newContext({
      viewport: { width: 390, height: 844 },
      serviceWorkers: "block",
    });

    // 개발용 테스트 주소 하나만 허용합니다.
    // 이 제한 자체가 완전한 네트워크 격리는 아닙니다.
    await context.route("**/*", async route => {
      if (route.request().url() === TEST_URL) {
        return route.continue();
      }
      // 실제 정책 abort 성공만 차단 근거로 전달합니다.
      await route.abort();
      network?.markPolicyBlocked(route.request());
      redirect?.markPolicyBlocked(route.request());
    });

    const page = await context.newPage();
    observer = createObserver(page, context, job.scanId, {
      observeNetwork: false,
      observeNavigation: false,
    });
    // 최초 접속 이전에 등록하고, 기존 observer의 중복 수집은 끕니다.
    network = createNetworkAnalyzer(page);
    redirect = createRedirectAnalyzer(page, { initialUrl: job.url });
    dom = createDomAnalyzer(page);

    const response = await page.goto(job.url, {
      waitUntil: "load",
      timeout: 10000,
    });

    job.finalUrl = redirect.result().finalUrl;
    job.httpStatus = response ? response.status() : null;

    const directory = `/tmp/seonbaldae-scans/${job.scanId}`;
    await fs.mkdir(directory, { recursive: true });

    await page.screenshot({
      path: `${directory}/shot.tmp.png`,
      fullPage: true,
      timeout: 5000,
    });

    if (expired) throw new Error("timeout");

    await fs.rename(
      `${directory}/shot.tmp.png`,
      `${directory}/shot.png`
    );

    job.capturedAt = new Date().toISOString();
    job.screenshotRef = `internal:${job.scanId}:png`;
    job.screenshotStatus = "ready";

    // PNG 준비 상태는 전체 분석 상태와 독립적입니다.
    // 기존 짧은 관찰 구간 동안에도 이미지는 조회할 수 있습니다.
    await new Promise(resolve => setTimeout(resolve, 1000));
    if (expired) throw new Error("timeout");
    await dom.collect();
    if (expired) throw new Error("timeout");

    job.evidence.push({
      id: `${job.scanId}-navigation`,
      kind: "navigation",
      source: "browser",
      observedAt: new Date().toISOString(),
      summary: "허가된 테스트 페이지 방문을 완료했습니다.",
      data: { httpStatus: job.httpStatus },
    });

    job.status = "completed";
  } catch (e) {
    job.status = "failed";
    if (job.screenshotStatus !== "ready") job.screenshotStatus = "failed";
    job.errorCode = expired ? "worker_timeout" : "browser_error";
    job.limitations.push("브라우저 검사 또는 캡처를 완료하지 못했습니다.");
    console.error(job.scanId, job.errorCode);
  } finally {
    clearTimeout(timer);
    // 닫기 이벤트는 관찰 대상이 아니므로 브라우저 종료 전에 해제합니다.
    network?.stop();
    redirect?.stop();
    dom?.stop();
    observer?.stop();
    job.networkAnalysis = network?.result() ?? null;
    job.redirectAnalysis = redirect?.result() ?? null;
    job.domAnalysis = dom?.result() ?? null;
    job.finalUrl = job.redirectAnalysis?.finalUrl ?? null;
    if (observer) {
      if (job.domAnalysis) {
        observer.record("dom_observation", "렌더링된 필드와 폼 메타데이터를 관찰했습니다. 제출은 수행하지 않았습니다.", job.domAnalysis);
      }
      for (const record of dom?.observations() ?? []) {
        observer.record(record.kind, "DOM/Form 관찰 범위와 메타데이터입니다.", record);
      }
      for (const record of network?.observations() ?? []) {
        const kinds = { attempted: "network_attempt", response_received: "network_response", network_failed: "network_failure", policy_blocked: "policy_blocked_request" };
        observer.record(kinds[record.outcome], "접속 시도·응답·실패·정책 차단을 구분한 관찰입니다.", record);
      }
      for (const record of redirect?.observations() ?? []) {
        observer.record(`redirect_${record.kind}`, "메인 프레임의 실제 이동과 이동 시도를 구분한 관찰입니다.", record);
      }
      const observed = observer.result();
      job.signals.push(...observed.signals);
      job.evidence.push(...observed.evidence);
      if (observed.evidence.length >= 100) job.limitations.push("증거 저장 상한에 도달하여 일부 메타데이터가 생략됐습니다.");
    }
    job.limitations = [...new Set([
      ...job.limitations,
      ...(network?.limitations() ?? []),
      ...(redirect?.limitations() ?? []),
      ...(dom?.limitations() ?? []),
      "초기 로딩과 짧은 관찰 구간만 검사했으며 사용자 상호작용은 수행하지 않았습니다.",
    ])];
    if (browser) await browser.close().catch(() => {});
    busy = false;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://worker");

    if (req.method === "GET" &&
        url.pathname === "/internal/health") {
      return json(res, 200, {
        status: "ok",
        service: "seonbaldae-worker",
      });
    }

    // 우리가 만든 무해한 테스트 페이지입니다.
    if (req.method === "GET" &&
        url.pathname === "/demo/normal") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
      });

      return res.end(`<!doctype html>
        <html lang="ko">
        <meta charset="utf-8">
        <title>선발대 테스트</title>
        <style>
          body {
            padding: 32px;
            background: #eef6f2;
            color: #183d35;
            font-family: sans-serif;
          }
          article {
            padding: 24px;
            background: white;
            border-radius: 20px;
          }
        </style>
        <h1>선발대</h1>
        <article>
          <h2>브라우저 방문 성공</h2>
          <p>Docker 안에서 실행한 테스트 페이지입니다.</p>
        </article>
        </html>`);
    }

    if (req.method === "POST" &&
        url.pathname === "/internal/jobs") {
      const input = await readBody(req);
      const { scanId, url: target } = input;
      const timeoutMs = input.timeoutMs ?? 30000;

      if (typeof scanId !== "string" ||
          !/^[A-Za-z0-9_-]{1,64}$/.test(scanId)) {
        return error(res, 400, "invalid_scan_id", "scanId 형식 오류");
      }

      if (target !== TEST_URL) {
        return error(res, 422, "target_not_allowed",
          "현재는 지정된 테스트 주소만 방문할 수 있습니다.");
      }

      if (!Number.isInteger(timeoutMs) ||
          timeoutMs < 1000 || timeoutMs > 30000) {
        return error(res, 400, "invalid_timeout",
          "timeoutMs는 1000~30000 정수여야 합니다.");
      }

      const existing = jobs.get(scanId);

      if (existing) {
        if (existing.url !== target ||
            existing.timeoutMs !== timeoutMs) {
          return error(res, 409, "job_conflict",
            "같은 scanId에 다른 요청을 사용할 수 없습니다.");
        }

        return json(res, 200, {
          scanId,
          status: existing.status,
          acceptedAt: existing.acceptedAt,
        });
      }

      if (busy) {
        return error(res, 429, "worker_busy",
          "현재 다른 작업을 처리하고 있습니다.");
      }

      const job = {
        scanId,
        url: target,
        timeoutMs,
        status: "queued",
        acceptedAt: new Date().toISOString(),
        finalUrl: null,
        httpStatus: null,
        screenshotRef: null,
        screenshotStatus: "pending",
        capturedAt: null,
        networkAnalysis: null,
        redirectAnalysis: null,
        domAnalysis: null,
        signals: [],
        evidence: [],
        limitations: [
          "개발용 테스트 페이지 방문·캡처만 수행합니다.",
          "악성 여부 판정과 고급 동적 분석은 수행하지 않았습니다.",
        ],
        errorCode: null,
      };

      jobs.set(scanId, job);
      busy = true;

      json(res, 202, {
        scanId,
        status: "queued",
        acceptedAt: job.acceptedAt,
      });

      setImmediate(() => {
        void runJob(job).catch(e => {
          busy = false;
          job.status = "failed";
          job.errorCode = "worker_error";
          console.error(job.scanId, "worker_error");
        });
      });
      return;
    }

    const match = url.pathname.match(
      /^\/internal\/jobs\/([A-Za-z0-9_-]{1,64})(\/screenshot)?$/
    );

    if (req.method === "GET" && match) {
      const scanId = match[1];
      const job = jobs.get(scanId);

      if (!job) {
        return error(res, 404, "job_not_found", "작업이 없습니다.");
      }

      if (match[2]) {
        if (job.screenshotStatus !== "ready") {
          return error(res, 409,
            job.screenshotStatus === "failed"
              ? "screenshot_failed"
              : "screenshot_not_ready",
            "이미지를 제공할 수 없습니다.");
        }

        const image = await fs.readFile(
          `/tmp/seonbaldae-scans/${scanId}/shot.png`
        );

        res.writeHead(200, {
          "Content-Type": "image/png",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        return res.end(image);
      }

      const { url: target, timeoutMs, ...result } = job;
      return json(res, 200, result);
    }

    error(res, 404, "not_found", "구현되지 않은 경로입니다.");
  } catch (e) {
    console.error("Worker request failed");
    error(res, 400, "request_error", "요청 처리에 실패했습니다.");
  }
});

server.listen(4000, "0.0.0.0", () => {
  console.log("선발대 Worker 서버 실행: 4000");
});
