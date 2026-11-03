const http = require("node:http");
const fs = require("node:fs/promises");
const { isIP } = require("node:net");
const { chromium } = require("playwright");
const { createObserver } = require("./observer.cjs");
const { createNetworkAnalyzer } = require("./network-analyzer.cjs");
const { createRedirectAnalyzer } = require("./redirect-analyzer.cjs");
const { createDomAnalyzer } = require("./dom-analyzer.cjs");

const jobs = new Map();
const TEST_URL = "http://127.0.0.1:4000/demo/normal";
const PUBLIC_PREVIEW = process.env.QR_GUARD_PUBLIC_PREVIEW === "true";
let busy = false;

function publicTarget(value) {
  try {
    if (typeof value !== "string" || value.length > 2048 || /[\s\\\x00-\x1f\x7f]/.test(value) ||
        !/^https?:\/\//i.test(value) || value.split("/")[2].includes("@")) return false;
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password ||
        (url.port && url.port !== (url.protocol === "http:" ? "80" : "443"))) return false;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    if (!host || host === "localhost" || /\.(localhost|local|internal)$/.test(host)) return false;
    if (isIP(host) === 4) {
      const [a, b] = host.split(".").map(Number);
      if (a === 0 || a === 10 || a === 127 || a >= 224 ||
          (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
          (a === 172 && b >= 16 && b <= 31) || (a === 192 && [0, 168].includes(b)) ||
          (a === 198 && [18, 19, 51].includes(b)) || (a === 203 && b === 0)) return false;
      return true;
    }
    // Literal IPv6 and non-DNS URL spellings are not supported by the IPv4 relay.
    return !host.includes(":") && host.includes(".") && /^[a-z0-9.-]+$/.test(host);
  } catch { return false; }
}

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
  let page;
  let onNavigationResponse;
  let expired = false;
  let completed = false;

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
      ...(job.publicPreview ? { args: ["--proxy-bypass-list=<-loopback>", "--disable-quic",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"] } : {}),
    });

    if (expired) throw new Error("timeout");

    const context = await browser.newContext({
      viewport: { width: 390, height: 844 },
      serviceWorkers: "block",
      acceptDownloads: false,
      ...(job.publicPreview ? { proxy: { server: "http://127.0.0.1:3128", bypass: "" } } : {}),
    });

    // Every public request still crosses the DNS-validating host relay. The
    // container has no network interface other than loopback; routing is defense
    // in depth, not the egress boundary. Never submit a page's data or forms.
    await context.route("**/*", async route => {
      const request = route.request();
      let readOnly = ["GET", "HEAD"].includes(request.method());
      try { readOnly &&= request.postDataBuffer() === null; } catch { readOnly = false; }
      let belongsToPage = true;
      try { belongsToPage = !page || request.frame().page() === page; } catch { belongsToPage = false; }
      const permitted = job.publicPreview ? publicTarget(request.url()) : request.url() === TEST_URL;
      if (readOnly && belongsToPage && permitted) {
        return route.continue();
      }
      // 실제 정책 abort 성공만 차단 근거로 전달합니다.
      await route.abort();
      network?.markPolicyBlocked(route.request());
      redirect?.markPolicyBlocked(route.request());
    });
    // WebSockets bypass HTTP routing in Chromium unless separately intercepted.
    await context.routeWebSocket("**/*", socket => socket.close());

    page = await context.newPage();
    onNavigationResponse = response => {
      try {
        const request = response.request();
        if (request.isNavigationRequest() && request.frame() === page.mainFrame()) job.httpStatus = response.status();
      } catch { /* An inaccessible response cannot establish a completed navigation. */ }
    };
    page.on("response", onNavigationResponse);
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

    // The private job result needs the exact committed URL for final threat
    // lookup and explicit navigation. Observation metadata stays redacted.
    const capturedUrl = page.url();
    job.finalUrl = capturedUrl;
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

    job.finalUrl = page.url();
    if (job.finalUrl !== capturedUrl) {
      await page.screenshot({ path: `${directory}/shot.tmp.png`, fullPage: true, timeout: 5000 });
      if (expired) throw new Error("timeout");
      await fs.rename(`${directory}/shot.tmp.png`, `${directory}/shot.png`);
      job.capturedAt = new Date().toISOString();
    }
    job.evidence.push({
      id: `${job.scanId}-navigation`,
      kind: "navigation",
      source: "browser",
      observedAt: new Date().toISOString(),
      summary: "격리 브라우저에서 읽기 전용 페이지 관찰을 완료했습니다.",
      data: { httpStatus: job.httpStatus },
    });

    completed = true;
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
    if (page && onNavigationResponse) page.off("response", onNavigationResponse);
    job.networkAnalysis = network?.result() ?? null;
    job.redirectAnalysis = redirect?.result() ?? null;
    job.domAnalysis = dom?.result() ?? null;
    // Never replace the committed destination with a redacted metadata URL.
    if (!job.finalUrl) job.finalUrl = job.redirectAnalysis?.finalUrl ?? null;
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
    if (completed) job.status = "completed";
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

      const publicPreview = PUBLIC_PREVIEW && publicTarget(target);
      if (target !== TEST_URL && !publicPreview) {
        return error(res, 422, "target_not_allowed",
          "방문 정책에 맞는 주소만 검사할 수 있습니다.");
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
        publicPreview: target !== TEST_URL && publicPreview,
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
        limitations: target === TEST_URL ? [
          "개발용 테스트 페이지 방문·캡처만 수행합니다.",
          "악성 여부 판정과 고급 동적 분석은 수행하지 않았습니다.",
        ] : ["공개 웹 페이지를 읽기 전용으로 관찰했으며 로그인·입력·폼 제출은 수행하지 않았습니다."],
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

      const { url: target, timeoutMs, publicPreview, ...result } = job;
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
