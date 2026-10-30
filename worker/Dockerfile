FROM mcr.microsoft.com/playwright:v1.64.1-noble

WORKDIR /app

ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

RUN npm init -y \
    && npm install --save-exact playwright@1.64.1

COPY browser.cjs .

USER pwuser

CMD ["node", "browser.cjs"]
