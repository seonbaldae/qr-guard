const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { decideVerdict } = require("./verdict.cjs");

const ROOT = __dirname;
const BASE = "http://127.0.0.1:4000";
const TEST_URL = `${BASE}/demo/normal`;

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
        throw new Error(`Worker HTTP ${response.status}: ${await response.text()}`);
    }

    return response.json();
}

async function main() {
    // Docker에 연결할 로컬 파일을 먼저 확인합니다.
    for (const file of [
        "run-phishpedia.py",
        "analyze-brand.py",
        ".cache/LOGO_FEATS.npy",
        ".cache/LOGO_FILES.npy",
    ]) {
        await fs.access(path.join(ROOT, file));
    }

    const scanId = `scan-${randomUUID()}`;
    const directory = path.join(ROOT, "phish-input", scanId);

    await fs.mkdir(directory, { recursive: true });

    const result = {
        scanId,
        requestedUrl: TEST_URL,
        executionStatus: "running",
        verdict: "unknown",
        verdictReasons: [],
        staticAnalysis: { status: "not_run", signals: [] },
        threatAnalysis: { status: "not_run", providers: [] },
        browserAnalysis: { status: "not_run" },
        brandAnalysis: { status: "not_run" },
    };

    try {
        console.error("[1/3] Worker에 방문·캡처 요청");

        await requestJson(`${BASE}/internal/jobs`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scanId,
                url: TEST_URL,
                timeoutMs: 30000,
            }),
        });

        const deadline = Date.now() + 45000;
        let job;

        while (Date.now() < deadline) {
            job = await requestJson(`${BASE}/internal/jobs/${scanId}`);

            if (["completed", "failed"].includes(job.status)) break;

            await new Promise(resolve => setTimeout(resolve, 500));
        }

        result.browserAnalysis = job ?? { status: "unknown" };

        if (
            job?.scanId !== scanId ||
            job.status !== "completed" ||
            job.screenshotStatus !== "ready" ||
            !job.finalUrl
        ) {
            throw new Error(
                `브라우저 검사를 완료하지 못했습니다: ${
                    job?.errorCode || job?.status || "timeout"
                }`
            );
        }

        console.error("[2/3] 같은 작업의 최종 URL·PNG 저장");

        const imageResponse = await fetch(
            `${BASE}/internal/jobs/${scanId}/screenshot`,
            { signal: AbortSignal.timeout(10000) }
        );

        if (!imageResponse.ok) {
            throw new Error(`PNG 수신 실패: HTTP ${imageResponse.status}`);
        }

        const image = Buffer.from(await imageResponse.arrayBuffer());

        if (
            image.subarray(0, 8).toString("hex") !==
            "89504e470d0a1a0a"
        ) {
            throw new Error("Worker 응답이 PNG가 아닙니다.");
        }

        await fs.writeFile(path.join(directory, "shot.png"), image);
        await fs.writeFile(
            path.join(directory, "info.txt"),
            job.finalUrl,
            "utf8"
        );

        console.error("[3/3] 격리된 Phishpedia에서 분석");

        const containerName = `seonbaldae-brand-${scanId}`;

        function mount(source, target, readonly = true) {
            return [
                "--mount",
                `type=bind,source=${source},target=${target}${
                    readonly ? ",readonly" : ""
                }`,
            ];
        }

        const dockerArgs = [
            "run",
            "--rm",
            "--name", containerName,
            "--platform", "linux/amd64",
            "--network", "none",
            ...mount(
                path.join(ROOT, "run-phishpedia.py"),
                "/opt/phishpedia/run-phishpedia.py"
            ),
            ...mount(
                path.join(ROOT, "analyze-brand.py"),
                "/opt/phishpedia/analyze-brand.py"
            ),
            ...mount(
                path.join(ROOT, ".cache/LOGO_FEATS.npy"),
                "/opt/phishpedia/LOGO_FEATS.npy"
            ),
            ...mount(
                path.join(ROOT, ".cache/LOGO_FILES.npy"),
                "/opt/phishpedia/LOGO_FILES.npy"
            ),
            // 이번 작업 폴더만 읽기·쓰기 가능하게 연결합니다.
            ...mount(directory, `/input/${scanId}`, false),
            "seonbaldae-phishpedia",
            "pixi", "run", "python", "-u",
            "analyze-brand.py",
            "--input", `/input/${scanId}`,
        ];

        result.brandAnalysis = { status: "running" };

        let execution;

        try {
            execution = spawnSync("docker", dockerArgs, {
                stdio: ["ignore", "inherit", "inherit"],
                timeout: 180000,
            });
        } finally {
            // 시간 초과 시에도 이번 작업의 컨테이너를 정리합니다.
            spawnSync("docker", ["rm", "-f", containerName], {
                stdio: "ignore",
                timeout: 10000,
            });
        }

        if (execution.error) throw execution.error;

        const brandResult = JSON.parse(
            await fs.readFile(
                path.join(directory, "brand-analysis.json"),
                "utf8"
            )
        );

        if (
            brandResult.scanId !== scanId ||
            brandResult.finalUrl !== job.finalUrl
        ) {
            throw new Error("브라우저 작업과 브랜드 분석 결과가 일치하지 않습니다.");
        }

        result.brandAnalysis = brandResult.brandAnalysis;

        if (
            execution.status !== 0 ||
            result.brandAnalysis?.status !== "completed"
        ) {
            throw new Error("Phishpedia 분석에 실패했습니다.");
        }

        result.executionStatus = "completed";
    } catch (error) {
        result.executionStatus = "failed";
        result.error = { message: error.message };

        if (result.brandAnalysis.status === "running") {
            result.brandAnalysis = {
                status: "failed",
                signal: "unknown",
            };
        }

        process.exitCode = 1;
    }

    const decision = decideVerdict(result);
    result.verdict = decision.verdict;
    result.verdictReasons = decision.reasons;

    const output = path.join(directory, "scan-result.json");

    await fs.writeFile(
        output,
        JSON.stringify(result, null, 2),
        "utf8"
    );

    console.log(JSON.stringify(result, null, 2));
    console.error(`결과 저장: ${output}`);
}

main().catch(error => {
    console.error(`실행 준비 실패: ${error.message}`);
    process.exitCode = 1;
});
