const { chromium } = require("playwright");

async function main() {
  const browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
  });

  try {
    const page = await browser.newPage({
      viewport: { width: 390, height: 844 },
    });

    // 첫 단계는 외부 사이트 대신 직접 만든 화면만 실행합니다.
    await page.setContent(`
      <!doctype html>
      <html lang="ko">
      <meta charset="utf-8">
      <style>
        body {
          margin: 0;
          padding: 40px 24px;
          background: #ecf6f1;
          color: #143d36;
          font-family: sans-serif;
        }
        h1 { font-size: 42px; }
        section {
          padding: 24px;
          background: white;
          border-radius: 20px;
        }
      </style>
      <h1>선발대</h1>
      <section>
        <h2>브라우저 실행 성공</h2>
        <p>이 화면은 Docker 컨테이너 안에서 실행됐습니다.</p>
        <p>다음 단계에서는 이 화면을 미리보기로 전달합니다.</p>
      </section>
      </html>
    `);

    await page.screenshot({
      path: "/tmp/preview.png",
      fullPage: true,
    });

    console.log("성공: /tmp/preview.png 저장 완료");
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
