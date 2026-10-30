// In-process Worker API regressions with explicit browser/fs doubles.
// Actual Chromium + PNG behavior is verified separately in isolated Docker.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { EventEmitter } = require("node:events");

const workerDirectory = path.resolve(__dirname, "..");
const normalUrl = "http://127.0.0.1:4000/demo/normal";

function mount({ failScreenshot = false, holdDom = false, failDom = false, blockedNavigation = false } = {}) {
  let handler;
  let routeHandler;
  const scheduled = [];
  const files = new Map();
  let releaseDom;
  let domStarted;
  let domResult = null;
  const domGate = new Promise(resolve => { releaseDom = resolve; });
  const domEntered = new Promise(resolve => { domStarted = resolve; });
  const page = new EventEmitter();
  const context = new EventEmitter();
  const frame = { url: () => normalUrl };
  const request = {
    url: () => normalUrl, method: () => "GET", resourceType: () => "document",
    isNavigationRequest: () => true, frame: () => frame, redirectedFrom: () => null,
    failure: () => null,
  };
  const response = {
    url: () => normalUrl, request: () => request, status: () => 200,
    headers: () => ({}), headerValue: async () => null,
  };
  page.mainFrame = () => frame;
  page.url = () => normalUrl;
  page.locator = () => ({ evaluateAll: async () => [], count: async () => 0 });
  page.goto = async () => {
    assert.ok(page.listenerCount("request") > 0, "listeners must precede navigation");
    page.emit("request", request);
    await routeHandler({ request: () => request, continue: async () => {}, abort: async () => {} });
    page.emit("response", response);
    page.emit("framenavigated", frame);
    if (blockedNavigation) {
      const blocked = { ...request, url: () => "https://blocked.example.test/login?token=secret-sentinel" };
      page.emit("request", blocked);
      await routeHandler({ request: () => blocked, continue: async () => assert.fail("policy must not continue"),
        abort: async () => page.emit("requestfailed", blocked) });
    }
    return response;
  };
  page.screenshot = async ({ path: target }) => {
    if (failScreenshot) throw new Error("controlled screenshot failure");
    files.set(target, Buffer.from("explicit-unit-test-image-double"));
  };
  context.route = async (_pattern, callback) => { routeHandler = callback; };
  context.newPage = async () => page;
  const browser = { newContext: async () => context, close: async () => {} };
  vm.runInNewContext(fs.readFileSync(path.join(workerDirectory, "worker.cjs"), "utf8"), {
    require(name) {
      if (name === "node:http") return { createServer(callback) {
        handler = callback;
        return { listen(_port, _host, ready) { ready(); } };
      } };
      if (name === "node:fs/promises") return {
        mkdir: async () => {},
        rename: async (from, to) => { files.set(to, files.get(from)); files.delete(from); },
        readFile: async target => files.get(target),
      };
      if (name === "playwright") return { chromium: { launch: async () => browser } };
      if (name === "./dom-analyzer.cjs") return { createDomAnalyzer() { return {
        async collect() {
          domStarted();
          assert.ok([...files.keys()].some(target => target.endsWith("/shot.png")), "PNG precedes DOM collection");
          if (holdDom) await domGate;
          if (failDom) throw new Error("controlled DOM failure");
          domResult = { pageTitle: "Controlled demo", passwordFieldCount: 0, sensitiveFieldTypes: [], forms: [] };
          return domResult;
        },
        result: () => domResult, observations: () => [], limitations: () => [], stop() {},
      }; } };
      if (name.startsWith("./")) return require(path.join(workerDirectory, name));
      return require(name);
    },
    URL, Buffer,
    console: { log() {}, error() {} },
    setImmediate: callback => scheduled.push(callback),
    setTimeout(callback, delay) {
      if (delay === 1000) { queueMicrotask(callback); return null; }
      return setTimeout(callback, delay);
    },
    clearTimeout,
  }, { filename: "worker.cjs" });

  async function call(method, url, body) {
    return new Promise((resolve, reject) => {
      const req = { method, url, async *[Symbol.asyncIterator]() {
        if (body !== undefined) yield Buffer.from(JSON.stringify(body));
      } };
      const res = { writeHead(status, headers) { this.status = status; this.headers = headers; },
        end(data) {
          const json = this.headers["Content-Type"].startsWith("application/json");
          resolve({ status: this.status, headers: this.headers, body: json ? JSON.parse(data) : data });
        },
      };
      Promise.resolve(handler(req, res)).catch(reject);
    });
  }
  function startJob() {
    assert.equal(scheduled.length, 1);
    scheduled.shift()();
  }
  async function waitForJob() {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      await new Promise(resolve => setImmediate(resolve));
      const current = await call("GET", "/internal/jobs/integration");
      if (["completed", "failed"].includes(current.body.status)) return current.body;
    }
    throw new Error("unit test job did not settle");
  }
  async function runJob() { startJob(); return waitForJob(); }
  async function waitForDom() {
    let timer;
    try { await Promise.race([domEntered, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("DOM collector was not called")), 1000);
    })]); } finally { clearTimeout(timer); }
  }
  return { call, runJob, startJob, waitForJob, waitForDom, releaseDom, page, context, files };
}

test("jobs 202 -> completed -> image 200 includes additive analysis fields", async () => {
  const worker = mount();
  const request = { scanId: "integration", url: normalUrl, timeoutMs: 20000 };
  const created = await worker.call("POST", "/internal/jobs", request);
  assert.equal(created.status, 202);
  assert.equal(created.body.status, "queued");
  const job = await worker.runJob();
  assert.equal(job.status, "completed");
  assert.deepEqual(job.networkAnalysis, {
    requestHosts: ["127.0.0.1"], requestCount: 1, blockedRequestCount: 0,
  });
  assert.deepEqual(job.redirectAnalysis, { redirected: false, finalUrl: normalUrl, redirectChain: [] });
  assert.deepEqual(job.domAnalysis, { pageTitle: "Controlled demo", passwordFieldCount: 0, sensitiveFieldTypes: [], forms: [] });
  const image = await worker.call("GET", "/internal/jobs/integration/screenshot");
  assert.equal(image.status, 200);
  assert.equal(image.headers["Content-Type"], "image/png");
  assert.equal((await worker.call("POST", "/internal/jobs", request)).status, 200);
  assert.equal((await worker.call("POST", "/internal/jobs", { ...request, timeoutMs: 19000 })).status, 409);
  assert.equal((await worker.call("GET", "/internal/jobs/missing")).status, 404);
  assert.equal((await worker.call("POST", "/internal/jobs", { ...request, scanId: "other", url: "https://example.test/" })).status, 422);
  assert.equal(job.evidence.some(item => ["network_request", "navigation_response"].includes(item.kind)), false);
  const ids = new Set(job.evidence.map(item => item.id));
  assert.equal(ids.size, job.evidence.length);
  assert.ok(job.signals.every(signal => signal.evidenceIds.every(id => ids.has(id))));
  assert.equal(worker.page.listenerCount("request"), 0);
  assert.equal(worker.page.listenerCount("response"), 0);
  assert.equal(worker.page.listenerCount("requestfailed"), 0);
  assert.equal(worker.page.listenerCount("framenavigated"), 0);
});

test("screenshot failure retains observed analysis and detaches listeners", async () => {
  const worker = mount({ failScreenshot: true });
  await worker.call("POST", "/internal/jobs", { scanId: "integration", url: normalUrl, timeoutMs: 20000 });
  const job = await worker.runJob();
  assert.equal(job.status, "failed");
  assert.equal(job.screenshotStatus, "failed");
  assert.equal(job.networkAnalysis.requestCount, 1);
  assert.equal(job.redirectAnalysis.finalUrl, normalUrl);
  assert.equal((await worker.call("GET", "/internal/jobs/integration/screenshot")).status, 409);
  assert.equal(worker.page.listenerCount("request"), 0);
  assert.equal(worker.page.listenerCount("response"), 0);
  assert.equal(worker.page.listenerCount("framenavigated"), 0);
});

test("PNG is available while DOM analysis is still running", async () => {
  const worker = mount({ holdDom: true });
  await worker.call("POST", "/internal/jobs", { scanId: "integration", url: normalUrl, timeoutMs: 20000 });
  worker.startJob();
  try {
    await worker.waitForDom();
    const job = (await worker.call("GET", "/internal/jobs/integration")).body;
    assert.equal(job.status, "running");
    assert.equal(job.screenshotStatus, "ready");
    assert.equal((await worker.call("GET", "/internal/jobs/integration/screenshot")).status, 200);
  } finally { worker.releaseDom(); }
  assert.equal((await worker.waitForJob()).status, "completed");
});

test("later DOM failure does not revoke an already ready PNG", async () => {
  const worker = mount({ failDom: true });
  await worker.call("POST", "/internal/jobs", { scanId: "integration", url: normalUrl, timeoutMs: 20000 });
  const job = await worker.runJob();
  assert.equal(job.status, "failed");
  assert.equal(job.screenshotStatus, "ready");
  assert.equal(job.domAnalysis, null);
  assert.equal((await worker.call("GET", "/internal/jobs/integration/screenshot")).status, 200);
});

test("actual policy hook marks blocked navigation without changing final URL", async () => {
  const worker = mount({ blockedNavigation: true });
  await worker.call("POST", "/internal/jobs", { scanId: "integration", url: normalUrl, timeoutMs: 20000 });
  const job = await worker.runJob();
  assert.deepEqual(job.networkAnalysis, {
    requestHosts: ["127.0.0.1", "blocked.example.test"], requestCount: 2, blockedRequestCount: 1,
  });
  assert.equal(job.redirectAnalysis.redirected, false);
  assert.equal(job.redirectAnalysis.finalUrl, normalUrl);
  assert.equal(job.redirectAnalysis.redirectChain[0].blocked, true);
  assert.equal(JSON.stringify(job).includes("secret-sentinel"), false);
});
