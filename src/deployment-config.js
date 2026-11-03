// Local defaults. The Vercel packaging step writes public deployment values
// into dist/src/deployment-config.js without changing these development values.
export const deploymentConfig = Object.freeze({
  scanTransport: 'job',
  scanMode: 'sandbox',
});
