const http = require("node:http");
const fs = require("node:fs/promises");
const { chromium } = require("playwright");
const { createObserver } = require("./observer.cjs");

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
    await context.route("**/*", route => {
      if (route.request().url() === TEST_URL) {
        return route.continue();
      }
      return route.abort();
    });

    const page = await context.newPage();
    const observer = createObserver(page, context, job.scanId);

    const response = await page.goto(job.url, {
      waitUntil: "load",
      timeout: 10000,
    });

    job.finalUrl = page.url();
    job.httpStatus = response ? response.status() : null;

    // 데모용으로 짧은 관찰 구간을 둡니다.
    await new Promise(resolve => setTimeout(resolve, 1000));

    await observer.collectDom();
    observer.stop();

    const observed = observer.result();
    job.signals.push(...observed.signals);
    job.evidence.push(...observed.evidence);
    job.limitations.push(
      "초기 로딩과 짧은 관찰 구간만 검사했으며 사용자 상호작용은 수행하지 않았습니다."
    );

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
    job.screenshotStatus = "failed";
    job.errorCode = expired ? "worker_timeout" : "browser_error";
    job.limitations.push("브라우저 검사 또는 캡처를 완료하지 못했습니다.");
    console.error(job.scanId, e.message);
  } finally {
    clearTimeout(timer);
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
          console.error(e.message);
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
    console.error(e.message);
    error(res, 400, "request_error", "요청 처리에 실패했습니다.");
  }
});

server.listen(4000, "0.0.0.0", () => {
  console.log("선발대 Worker 서버 실행: 4000");
});
