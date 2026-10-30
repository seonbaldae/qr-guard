const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createNetworkAnalyzer } = require('../network-analyzer.cjs');
const req = (url, method = 'GET', type = 'script') => ({ url: () => url, method: () => method, resourceType: () => type });
const response = (request, status) => ({ request: () => request, status: () => status });

test('captures distinct request identities and sorted hosts', () => {
  const page = new EventEmitter(); const a = createNetworkAnalyzer(page);
  const first = req('https://z.example/a');
  page.emit('request', first); page.emit('request', first); page.emit('request', req('https://a.example/b'));
  assert.deepEqual(a.result(), { requestHosts: ['a.example', 'z.example'], requestCount: 2, blockedRequestCount: 0 });
});
test('distinguishes response, failure and explicit policy in any ordering', () => {
  const page = new EventEmitter(); const a = createNetworkAnalyzer(page);
  const allowed = req('https://allowed.test/a'), failed = req('https://failed.test/a'), blocked = req('https://blocked.test/a'), early = req('https://early.test/a');
  page.emit('request', allowed); page.emit('response', response(allowed, 503));
  page.emit('request', failed); page.emit('requestfailed', failed);
  page.emit('requestfailed', blocked); a.markPolicyBlocked(blocked); a.markPolicyBlocked(blocked); page.emit('request', blocked);
  a.markPolicyBlocked(early); page.emit('request', early); page.emit('requestfailed', early);
  assert.equal(a.result().requestCount, 4); assert.equal(a.result().blockedRequestCount, 2);
  const observations = a.observations();
  assert(observations.some(x => x.host === 'allowed.test' && x.outcome === 'response_received' && x.statusCode === 503));
  assert(observations.some(x => x.host === 'failed.test' && x.outcome === 'network_failed'));
  assert(!observations.some(x => x.host === 'failed.test' && x.outcome === 'policy_blocked'));
  assert(observations.some(x => x.host === 'blocked.test' && x.outcome === 'policy_blocked'));
  assert(observations.some(x => x.host === 'early.test' && x.outcome === 'attempted'));
});
test('bounds events, requests, hosts and observations and reports truncation', () => {
  const page = new EventEmitter(); const a = createNetworkAnalyzer(page, { maxRequests: 3, maxHosts: 2, maxEvents: 6, maxObservations: 2 });
  for (let i = 0; i < 50; i++) { const r = req(`https://h${i}.test/`); page.emit('request', r); page.emit('response', response(r, 200)); }
  assert(a.result().requestCount <= 3); assert(a.result().requestHosts.length <= 2); assert(a.observations().length <= 2); assert(a.limitations().length > 0);
});
test('sanitizes metadata and ignores non-http or invalid URLs', () => {
  const page = new EventEmitter(); const a = createNetworkAnalyzer(page);
  const r = req('https://secretuser:secretpass@example.test/secretpath?token=secrettoken#secrethash', 'secretmethod', 'secretresource');
  r.headers = () => { throw Error('headers must not be read'); }; r.postData = () => { throw Error('body must not be read'); };
  page.emit('request', r); page.emit('response', response(r, 404)); page.emit('request', req('data:text/plain,secretdata')); page.emit('request', req('not a URL'));
  const json = JSON.stringify([a.result(), a.observations(), a.limitations()]);
  for (const secret of ['secretuser','secretpass','secretpath','secrettoken','secrethash','secretmethod','secretresource','secretdata']) assert(!json.includes(secret));
  assert.deepEqual(a.result().requestHosts, ['example.test']);
});
test('validates limits and stops only its own listeners with detached snapshots', () => {
  for (const key of ['maxRequests', 'maxHosts', 'maxEvents', 'maxObservations']) for (const value of [-1, 1.5, Infinity, 10000000]) assert.throws(() => createNetworkAnalyzer(new EventEmitter(), { [key]: value }));
  const page = new EventEmitter(); let foreign = 0; page.on('request', () => foreign++);
  const a = createNetworkAnalyzer(page); const r = req('https://one.test/'); page.emit('request', r);
  const result = a.result(), obs = a.observations(), limitations = a.limitations();
  result.requestHosts.push('evil'); obs[0].host = 'evil'; limitations.push('evil');
  assert.deepEqual(a.result().requestHosts, ['one.test']); assert.equal(a.observations()[0].host, 'one.test'); assert(!a.limitations().includes('evil'));
  a.stop(); a.stop(); page.emit('request', req('https://two.test/')); a.markPolicyBlocked(r);
  assert.equal(foreign, 2); assert.equal(a.result().requestCount, 1); assert.equal(a.result().blockedRequestCount, 0);
  assert.equal(page.listenerCount('response'), 0); assert.equal(page.listenerCount('requestfailed'), 0); assert.equal(page.listenerCount('request'), 1);
});
