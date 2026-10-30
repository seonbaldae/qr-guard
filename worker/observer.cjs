function safeUrl(value, base) {
  try {
    const url = new URL(value, base);

    // 쿼리·해시·주소 안의 인증정보는 기록하지 않습니다.
    return `${url.origin}${url.pathname}`;
  } catch {
    return null;
  }
}

function createObserver(page, context, scanId) {
  const evidence = [];
  const signals = [];

  function add(kind, summary, data, severity = "info") {
    // 데모에서 기록이 무한히 커지지 않도록 제한합니다.
    if (evidence.length >= 100) return;

    const id = `${scanId}-observed-${evidence.length + 1}`;

    evidence.push({
      id,
      kind,
      source: "browser",
      observedAt: new Date().toISOString(),
      summary,
      data,
    });

    signals.push({
      id: `${id}-signal`,
      kind,
      severity,
      summary,
      source: "browser",
      evidenceIds: [id],
    });
  }

  function onResponse(response) {
    const request = response.request();

    if (
      request.isNavigationRequest() &&
      request.frame() === page.mainFrame()
    ) {
      const location = response.headers()["location"];

      add("navigation_response", "페이지 이동 응답을 관찰했습니다.", {
        url: safeUrl(response.url()),
        httpStatus: response.status(),
        redirectTo: location
          ? safeUrl(location, response.url())
          : null,
      });
    }
  }

  function onRequest(request) {
    // 요청 본문·헤더·쿠키·입력값은 수집하지 않습니다.
    add("network_request", "브라우저의 요청 대상을 관찰했습니다.", {
      url: safeUrl(request.url()),
      method: request.method(),
      resourceType: request.resourceType(),
    });
  }

  function onDownload(download) {
    add("download_attempt", "파일 다운로드 시도를 관찰했습니다.", {
      url: safeUrl(download.url()),
    }, "medium");

    // 파일은 받거나 실행하지 않습니다.
    void download.cancel().catch(() => {});
  }

  function onPopup(popup) {
    if (popup === page) return;

    add("popup_attempt", "추가 창 생성 시도를 관찰했습니다.", {});
    void popup.close().catch(() => {});
  }

  page.on("response", onResponse);
  page.on("request", onRequest);
  page.on("download", onDownload);
  context.on("page", onPopup);

  return {
    async collectDom() {
      // 코드는 방문 페이지에서 DOM을 읽기만 합니다.
      // 입력·버튼 클릭·폼 제출은 하지 않습니다.
      const forms = await page.locator("form").evaluateAll(nodes =>
        nodes.slice(0, 20).map(form => ({
          action: form.action,
          method: form.method,
          passwordCount:
            form.querySelectorAll('input[type="password"]').length,
        }))
      );

      for (const form of forms) {
        add("form_observation", "입력폼의 제출 대상과 필드를 확인했습니다.", {
          action: safeUrl(form.action, page.url()),
          method: form.method,
          passwordCount: form.passwordCount,
        });
      }

      const passwordCount =
        await page.locator('input[type="password"]').count();

      if (passwordCount > 0) {
        add("password_field",
          "비밀번호 입력 필드가 있습니다. 이것만으로 악성은 아닙니다.",
          { count: passwordCount });
      }

      return { formsCount: forms.length, passwordCount };
    },

    result() {
      return { signals, evidence };
    },

    stop() {
      page.off("response", onResponse);
      page.off("request", onRequest);
      page.off("download", onDownload);
      context.off("page", onPopup);
    },
  };
}

module.exports = { createObserver };
