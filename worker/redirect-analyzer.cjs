'use strict';
const { createHmac, randomBytes } = require('node:crypto');
const { isIP } = require('node:net');
const { getDomain } = require('tldts');

function createRedirectAnalyzer(page, { initialUrl, maxEntries = 50, maxEvents = 400, resolveRegisteredDomain = host => getDomain(host, { allowPrivateDomains: true }) } = {}) {
  const cap = value => Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
  maxEntries = cap(maxEntries); maxEvents = cap(maxEvents);
  const key = randomBytes(32);
  const chain = [], observations = [], limitations = [];
  const requests = new WeakMap();
  const blockedRequests = new WeakSet();
  let stopped = false, redirected = false, current = null;
  function note(s) { if (!limitations.includes(s)) limitations.push(s); }
  function parsed(value, base) {
    try {
      const u = new URL(value, base);
      if (!['http:', 'https:'].includes(u.protocol)) return null;
      const fingerprint = createHmac('sha256', key).update(u.href.split('#')[0]).digest('hex');
      const host = u.hostname.toLowerCase();
      const path = u.pathname.split('/').map((part, i, all) => {
        let decoded; try { decoded = decodeURIComponent(part); } catch { decoded = part; }
        const secretName = /^(?:token|access_token|id_token|auth|authorization|session|secret|password|passwd|api[-_]?key|code|jwt|reset|verify)$/i;
        const prev = i > 0 ? all[i - 1] : '';
        if ((i > 0 && secretName.test(prev)) || /(?:token|secret|password|api[-_]?key|session)[=:]/i.test(decoded) || /^[A-Za-z0-9_-]{24,}$/.test(decoded) || /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(decoded)) return '[redacted]';
        return part;
      }).join('/');
      return { url: u.origin + path, host, fingerprint };
    } catch { return null; }
  }
  const initial = parsed(initialUrl);
  function domain(host) {
    if (!host || isIP(host.replace(/^\[|\]$/g, '')) || host === 'localhost' || host.endsWith('.localhost')) return null;
    try { return resolveRegisteredDomain(host) || null; } catch { return null; }
  }
  function metadata(from, to) {
    const a = from && domain(from.host), b = to && domain(to.host);
    return { hostChanged: from && to ? from.host !== to.host : null, registeredDomainChanged: a && b ? a !== b : null };
  }
  function observe(kind, from, to, extra = {}) {
    if (observations.length >= maxEvents) { note('Observation limit reached; events may be omitted.'); return; }
    observations.push({ kind, from: from?.url || null, to: to?.url || null, ...metadata(from, to), ...extra });
  }
  function addEdge(from, to, statusCode, type, blocked) {
    if (!from || !to) return null;
    const edge = { from: from.url, to: to.url, statusCode, type, blocked };
    if (chain.length >= maxEntries) { note('Redirect chain limit reached; entries may be omitted.'); return null; }
    const record = { edge, fromKey: from.fingerprint, toKey: to.fingerprint, pending: true };
    chain.push(record); return record;
  }
  function mainRequest(req) {
    try { return req.isNavigationRequest() && req.frame() === page.mainFrame(); } catch { return false; }
  }
  function onRequest(req) {
    if (!mainRequest(req)) return;
    const target = parsed(req.url()); if (!target) return;
    let previous = null;
    try { const prior = req.redirectedFrom?.(); if (prior) previous = requests.get(prior)?.target || parsed(prior.url()); } catch {}
    const from = previous || current || initial;
    requests.set(req, { target, from });
    observe('attempt', from, target, { blocked: false });
  }
  function onResponse(response) {
    let req, status, location, source;
    try {
      req = response.request(); if (!mainRequest(req)) return;
      status = response.status(); if (![301, 302, 303, 307, 308].includes(status)) return;
      location = response.headers().location; if (!location) return;
      source = response.url();
    } catch { return; }
    const from = parsed(source), to = parsed(location, source); if (!from || !to) return;
    const existing = chain.find(x => x.fromKey === from.fingerprint && x.toKey === to.fingerprint && x.edge.blocked && x.edge.type === 'unknown');
    if (existing) { existing.edge.type = 'http'; existing.edge.statusCode = status; }
    else addEdge(from, to, status, 'http', false);
    observe('http_redirect', from, to, { statusCode: status });
  }
  function onNavigate(frame) {
    if (frame !== page.mainFrame()) return;
    let target; try { target = parsed(frame.url()); } catch { return; }
    if (!target) return;
    const from = current || initial;
    const changed = from && from.fingerprint !== target.fingerprint;
    if (initial && initial.fingerprint !== target.fingerprint) redirected = true;
    const httpTransition = chain.some(x => x.pending && x.toKey === target.fingerprint && x.edge.type === 'http' && !x.edge.blocked);
    if (changed && !httpTransition) addEdge(from, target, null, 'client_navigation', false);
    for (const edge of chain) edge.pending = false;
    observe('commit', from, target);
    current = target;
  }
  function markPolicyBlocked(req) {
    if (stopped || !mainRequest(req) || blockedRequests.has(req)) return;
    let target; try { target = parsed(req.url()); } catch { return; }
    if (!target) return;
    blockedRequests.add(req);
    const info = requests.get(req);
    let edge = chain.findLast(x => x.pending && x.toKey === target.fingerprint && !x.edge.blocked && x.edge.type === 'http');
    let from = info?.from || current || initial;
    if (edge) { edge.edge.blocked = true; from = { url: edge.edge.from, host: new URL(edge.edge.from).hostname, fingerprint: edge.fromKey }; }
    else edge = addEdge(from, target, null, 'unknown', true);
    observe('attempt', from, target, { blocked: true });
  }
  page.on('request', onRequest); page.on('response', onResponse); page.on('framenavigated', onNavigate);
  return {
    markPolicyBlocked,
    result: () => ({ redirected, finalUrl: current?.url || null, redirectChain: chain.map(x => ({ ...x.edge })) }),
    observations: () => observations.map(x => ({ ...x })),
    limitations: () => [...limitations],
    stop() { if (stopped) return; stopped = true; page.off('request', onRequest); page.off('response', onResponse); page.off('framenavigated', onNavigate); },
  };
}
module.exports = { createRedirectAnalyzer };
