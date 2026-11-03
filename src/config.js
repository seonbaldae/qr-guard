import { deploymentConfig } from './deployment-config.js';

// All requests use our API origin. Deployment settings contain no secrets.
export const frontendConfig = Object.freeze({
  apiBaseUrl: '',
  scanTransport: deploymentConfig.scanTransport,
  scanMode: deploymentConfig.scanMode,
  analyzePath: '/api/analyze',
  createScanPath: '/api/scans',
  scanPath: (scanId) => `/api/scans/${encodeURIComponent(scanId)}`,
  reportPath: (scanId) => `/api/scans/${encodeURIComponent(scanId)}/reports`,
  requestTimeoutMs: 270000,
  pollIntervalMs: 1200,
  demoDelayMs: 1400,
});
