const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createRedirectAnalyzer } = require('../redirect-analyzer.cjs');

function setup(initialUrl = 'https://a.example/start', options = {}) {
  const page = new EventEmitter();
  const main = { value: 'about:blank', url() { return this.value; } };
  const sub = { url: () => 'https://sub.example/' };
  page.mainFrame = () => main;
  const request = (url, frame = main) => ({ url: () => url, frame: () => frame, isNavigationRequest: () => true });
  const commit = (url, frame = main) => { if (frame === main) main.value = url; page.emit('framenavigated', frame); };
  const response = (req, status, location) => page.emit('response', { request: () => req, url: () => req.url(), status: () => status, headers: () => location ? { location } : {} });
  return { page, main, sub, request, commit, response, analyzer: createRedirectAnalyzer(page, { initialUrl, ...options }) };
}

test('initial commit is not a redirect', () => {
  const s = setup(); s.commit('https://a.example/start');
  assert.deepEqual(s.analyzer.result(), { redirected: false, finalUrl: 'https://a.example/start', redirectChain: [] });
});


test('R1 multi-hop HTTP redirects resolve relative locations, then commit', () => {
  const s = setup();
  const a = s.request('https://a.example/start'); s.page.emit('request', a); s.response(a, 302, '/next');
  const b = s.request('https://a.example/next'); s.page.emit('request', b); s.response(b, 307, 'https://b.example/end');
  s.commit('https://b.example/end');
  assert.deepEqual(s.analyzer.result(), { redirected: true, finalUrl: 'https://b.example/end', redirectChain: [
    { from: 'https://a.example/start', to: 'https://a.example/next', statusCode: 302, type: 'http', blocked: false },
    { from: 'https://a.example/next', to: 'https://b.example/end', statusCode: 307, type: 'http', blocked: false },
  ] });
});


test('R2 client commit and blocked attempt preserve last actual commit', () => {
  const s = setup(); s.commit('https://a.example/start'); s.commit('https://a.example/page');
  const r = s.request('https://other.example/blocked'); s.page.emit('request', r); s.analyzer.markPolicyBlocked(r);
  assert.equal(s.analyzer.result().redirected, true);
  assert.equal(s.analyzer.result().finalUrl, 'https://a.example/page');
  assert.deepEqual(s.analyzer.result().redirectChain.map(x => [x.type, x.blocked]), [['client_navigation', false], ['unknown', true]]);
  s.commit('https://a.example/after'); assert.equal(s.analyzer.result().finalUrl, 'https://a.example/after');
});

test('uncommitted and failed attempts and 304 are not redirects', () => {
  const s = setup(); s.commit('https://a.example/start');
  const r = s.request('https://b.example/'); s.page.emit('request', r); s.page.emit('requestfailed', r); s.response(r, 304, '/wrong');
  assert.equal(s.analyzer.result().redirected, false); assert.deepEqual(s.analyzer.result().redirectChain, []);
});

test('blocked HTTP edge is deduplicated regardless of event order', () => {
  for (const blockedFirst of [false, true]) {
    const s = setup(); s.commit('https://a.example/start'); const source = s.request('https://a.example/start'); const destination = s.request('https://b.example/');
    s.page.emit('request', source); s.page.emit('request', destination);
    if (blockedFirst) s.analyzer.markPolicyBlocked(destination);
    s.response(source, 302, 'https://b.example/');
    if (!blockedFirst) s.analyzer.markPolicyBlocked(destination);
    assert.deepEqual(s.analyzer.result().redirectChain, [{ from: 'https://a.example/start', to: 'https://b.example/', statusCode: 302, type: 'http', blocked: true }]);
    assert.equal(s.analyzer.result().finalUrl, 'https://a.example/start');
  }
});

test('subframes and non-http destinations ignored', () => {
  const s = setup(); s.commit('https://a.example/start');
  const r = s.request('https://b.example/', s.sub); s.page.emit('request', r); s.response(r, 302, '/there'); s.analyzer.markPolicyBlocked(r); s.commit('https://b.example/', s.sub);
  s.commit('about:blank'); s.commit('javascript:alert(1)');
  assert.deepEqual(s.analyzer.result(), {redirected:false, finalUrl:'https://a.example/start', redirectChain:[]});
});

test('PSL comparison respects co.uk, private hosting, and IP unknown', () => {
  const s = setup('https://a.foo.co.uk/'); s.commit('https://a.foo.co.uk/'); s.commit('https://b.foo.co.uk/'); s.commit('https://foo.github.io/'); s.commit('https://bar.github.io/'); s.commit('http://127.0.0.1/');
  const commits = s.analyzer.observations().filter(x => x.kind === 'commit');
  assert.equal(commits[1].hostChanged, true); assert.equal(commits[1].registeredDomainChanged, false);
  assert.equal(commits[3].registeredDomainChanged, true); assert.equal(commits[4].registeredDomainChanged, null);
});

test('records redact credentials query fragment and token path; query-only transition is detected', () => {
  const s = setup('https://user:pass@a.example/token/longsecretvalue?x=one#private');
  s.commit('https://user:pass@a.example/token/longsecretvalue?x=one#private');
  s.commit('https://user:pass@a.example/token/longsecretvalue?x=two#private');
  assert.equal(s.analyzer.result().redirected, true);
  const all = JSON.stringify([s.analyzer.result(), s.analyzer.observations(), s.analyzer.limitations()]);
  for (const secret of ['user', 'pass@', 'longsecretvalue', '?x=', '#private']) assert.equal(all.includes(secret), false);
});

test('caps snapshots and removes only own listeners on idempotent stop', () => {
  const s = setup(undefined, { maxEntries: 1, maxEvents: 2 });
  let calls = 0; s.page.on('framenavigated', () => calls++);
  s.commit('https://a.example/start'); s.commit('https://a.example/a'); s.commit('https://a.example/b');
  assert.equal(s.analyzer.result().redirectChain.length, 1); assert.equal(s.analyzer.observations().length, 2); assert.ok(s.analyzer.limitations().length);
  const snapshot = s.analyzer.result(); snapshot.redirectChain[0].to = 'bad'; assert.notEqual(s.analyzer.result().redirectChain[0].to, 'bad');
  s.analyzer.stop(); s.analyzer.stop(); s.commit('https://a.example/c'); assert.equal(calls, 4); assert.equal(s.analyzer.result().finalUrl, 'https://a.example/b');
});


test('repeated policy callback does not duplicate blocked edge', () => {
  const s = setup(); s.commit('https://a.example/start'); const r = s.request('https://b.example/');
  s.page.emit('request', r); s.analyzer.markPolicyBlocked(r); s.analyzer.markPolicyBlocked(r);
  assert.equal(s.analyzer.result().redirectChain.length, 1);
});

test('later navigation to previously visited HTTP destination is still a client transition', () => {
  const s = setup(); const a = s.request('https://a.example/start'); s.response(a, 302, 'https://b.example/'); s.commit('https://b.example/');
  s.commit('https://c.example/'); s.commit('https://b.example/');
  assert.equal(s.analyzer.result().redirectChain.at(-1).from, 'https://c.example/');
  assert.equal(s.analyzer.result().redirectChain.at(-1).to, 'https://b.example/');
});
