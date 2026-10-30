'use strict';

const METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']);
const TYPES = new Set(['document', 'stylesheet', 'image', 'media', 'font', 'script', 'texttrack', 'xhr', 'fetch', 'eventsource', 'websocket', 'manifest', 'other']);
const DEFAULTS = { maxRequests: 200, maxHosts: 50, maxEvents: 400, maxObservations: 200 };
const MAXIMUMS = { maxRequests: 10000, maxHosts: 10000, maxEvents: 20000, maxObservations: 10000 };

function createNetworkAnalyzer(page, options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('options must be an object');
  const limits = {};
  for (const key of Object.keys(DEFAULTS)) {
    const value = options[key] === undefined ? DEFAULTS[key] : options[key];
    if (!Number.isInteger(value) || value < 1 || value > MAXIMUMS[key]) throw new RangeError(`invalid ${key}`);
    limits[key] = value;
  }
  const seen = new WeakMap();
  const hosts = new Set();
  const records = [];
  const omissions = new Set();
  let events = 0, count = 0, blockedCount = 0, stopped = false;

  function acceptedEvent() {
    if (stopped) return false;
    if (events >= limits.maxEvents) { omissions.add('Network event limit reached; later events were not observed.'); return false; }
    events++;
    return true;
  }
  function identify(request) {
    if (!request || (typeof request !== 'object' && typeof request !== 'function')) return null;
    const previous = seen.get(request);
    if (previous) return previous;
    let url, method, resourceType;
    try {
      url = new URL(request.url());
      if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) return null;
      method = request.method(); resourceType = request.resourceType();
    } catch { return null; }
    if (count >= limits.maxRequests) { omissions.add('Request limit reached; later requests were not counted.'); return null; }
    const item = { host: url.hostname, method: METHODS.has(method) ? method : null, resourceType: TYPES.has(resourceType) ? resourceType : null, blocked: false, outcomes: new Set() };
    seen.set(request, item); count++;
    if (hosts.has(item.host) || hosts.size < limits.maxHosts) hosts.add(item.host);
    else omissions.add('Host limit reached; some request hosts were omitted.');
    add(item, 'attempted');
    return item;
  }
  function add(item, outcome, statusCode = null) {
    if (item.outcomes.has(outcome)) return;
    item.outcomes.add(outcome);
    if (records.length >= limits.maxObservations) { omissions.add('Observation limit reached; some metadata was omitted.'); return; }
    records.push({ host: item.host, method: item.method, statusCode, resourceType: item.resourceType, outcome });
  }
  function onRequest(request) { if (acceptedEvent()) identify(request); }
  function onResponse(response) {
    if (!acceptedEvent()) return;
    try {
      const item = identify(response.request());
      if (!item) return;
      const status = response.status();
      add(item, 'response_received', Number.isInteger(status) && status >= 100 && status <= 599 ? status : null);
    } catch { /* Malformed browser event: do not expose error text. */ }
  }
  function onFailed(request) {
    if (!acceptedEvent()) return;
    const item = identify(request);
    if (item) add(item, 'network_failed');
  }
  function markPolicyBlocked(request) {
    if (!acceptedEvent()) return;
    const item = identify(request);
    if (item && !item.blocked) { item.blocked = true; blockedCount++; add(item, 'policy_blocked'); }
  }
  page.on('request', onRequest);
  page.on('response', onResponse);
  page.on('requestfailed', onFailed);
  return {
    markPolicyBlocked,
    result: () => ({ requestHosts: [...hosts].sort(), requestCount: count, blockedRequestCount: blockedCount }),
    observations: () => records.map(record => ({ ...record })),
    limitations: () => [...omissions],
    stop() {
      if (stopped) return;
      stopped = true;
      page.off('request', onRequest); page.off('response', onResponse); page.off('requestfailed', onFailed);
    },
  };
}
module.exports = { createNetworkAnalyzer };
