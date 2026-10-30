FROM mcr.microsoft.com/playwright:v1.64.1-noble

ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV NODE_PATH=/opt/qr-deps/node_modules
ENV NODE_OPTIONS=--max-old-space-size=512

WORKDIR /app
COPY cloud/package.json cloud/package-lock.json /opt/qr-deps/
RUN npm ci --prefix /opt/qr-deps --omit=dev --ignore-scripts --no-audit --no-fund
COPY cloud/run.cjs /app/cloud/run.cjs
COPY destination-policy.cjs observer.cjs network-analyzer.cjs redirect-analyzer.cjs dom-analyzer.cjs /app/

USER pwuser
