import { QrCameraScanner } from './components/qr-camera-scanner.js';
import { QrScanPage } from './components/qr-scan-page.js';
import { QrLoadingPage } from './components/qr-loading-page.js';
import { QrSitePreview } from './components/qr-site-preview.js';
import { QrVerdictSummary } from './components/qr-verdict-summary.js';
import { QrResultPage } from './components/qr-result-page.js';
import { QrApp } from './components/qr-app.js';

for(const [name,component] of [
  ['qr-camera-scanner',QrCameraScanner],
  ['qr-scan-page',QrScanPage],['qr-loading-page',QrLoadingPage],['qr-site-preview',QrSitePreview],
  ['qr-verdict-summary',QrVerdictSummary],['qr-result-page',QrResultPage],['qr-app',QrApp],
]) customElements.define(name,component);
