// Frontend integration settings. These paths describe the proposed API contract;
// this static frontend does not create the backend routes.
export const frontendConfig = Object.freeze({
  apiBaseUrl: '',
  scanTransport: 'direct', // 'direct' or 'job'
  analyzePath: '/api/analyze',
  createScanPath: '/api/scans',
  scanPath: (scanId) => `/api/scans/${encodeURIComponent(scanId)}`,
  reportPath: (scanId) => `/api/scans/${encodeURIComponent(scanId)}/reports`,
  requestTimeoutMs: 30000,
  pollIntervalMs: 1200,
  demoDelayMs: 1400,
});
