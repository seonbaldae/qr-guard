FROM node:24-bookworm-slim

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV NODE_PATH=/opt/qr-deps/node_modules
ENV NODE_OPTIONS=--max-old-space-size=512

WORKDIR /app
COPY cloud/package.json cloud/package-lock.json /opt/qr-deps/
RUN npm ci --prefix /opt/qr-deps --omit=dev --ignore-scripts --no-audit --no-fund
RUN apt-get update \
    && apt-get install -y --no-install-recommends procps ca-certificates \
    && node /opt/qr-deps/node_modules/playwright/cli.js install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /ms-playwright
COPY cloud/run.cjs /app/cloud/run.cjs
COPY destination-policy.cjs observer.cjs network-analyzer.cjs redirect-analyzer.cjs dom-analyzer.cjs /app/

USER node
