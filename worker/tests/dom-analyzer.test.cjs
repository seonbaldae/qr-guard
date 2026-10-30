const test = require('node:test');
const assert = require('node:assert/strict');
const { createDomAnalyzer } = require('../dom-analyzer.cjs');

function element(tag, attrs = {}, children = [], shadowRoot = null) {
  return { tagName: tag.toUpperCase(), children, shadowRoot,
    getAttribute(name) { return Object.hasOwn(attrs, name) ? attrs[name] : null; } };
}
function frame(children, title = 'Login', baseURI = 'https://example.test/path/', url = baseURI) {
  return { async evaluate(fn, arg) {
    const previous = global.document;
    global.document = { title, baseURI, URL: url, children };
    try { return fn(arg); } finally { global.document = previous; }
  } };
}
function page(...frames) { return { frames: () => frames }; }

test('collects rendered password and relative form host without values', async () => {
  const password = element('input', { type: 'password', value: 'secret-sentinel' });
  const analyzer = createDomAnalyzer(page(frame([element('form', { method: 'POST', action: '../login?token=secret-sentinel' }, [password])])));
  assert.deepEqual(await analyzer.collect(), { pageTitle: 'Login', passwordFieldCount: 1, sensitiveFieldTypes: ['password'], forms: [{ method: 'post', actionHost: 'example.test' }] });
  assert(!JSON.stringify([analyzer.result(), analyzer.observations(), analyzer.limitations()]).includes('secret-sentinel'));
});


test('open shadow fields and frames are counted, with OTP and card metadata', async () => {
  const shadow = { children: [element('input', { autocomplete: 'one-time-code' }), element('input', { autocomplete: 'cc-number' })] };
  const a = createDomAnalyzer(page(frame([element('div', {}, [], shadow)]), frame([element('input', { type: 'password' })])));
  assert.deepEqual((await a.collect()).sensitiveFieldTypes, ['password', 'otp', 'payment_card']);
  assert.equal(a.result().passwordFieldCount, 1);
});

test('inspection failures and limits never produce an untrusted zero', async () => {
  const broken = { evaluate: async () => { throw Error('secret-sentinel'); } };
  const a = createDomAnalyzer(page(frame([]), broken));
  assert.equal(await a.collect(), null);
  assert(a.limitations().some(x => /frame/i.test(x)));
  assert(!JSON.stringify(a.limitations()).includes('secret-sentinel'));
  const b = createDomAnalyzer(page(frame([element('input'), element('input', {type:'password'})])), { maxFields: 1 });
  assert.equal(await b.collect(), null);
  assert(b.limitations().some(x => /field/i.test(x)));
});

test('bounded forms report comparison only with explicit official domain and snapshots are isolated', async () => {
  const forms = [element('form', {action:'https://other.test/x?token=secret-sentinel'}), element('form', {action:'/two'})];
  const a = createDomAnalyzer(page(frame(forms, 'https://example.test/?token=secret-sentinel')), {
    maxForms: 1, officialDomain:'official.test', resolveRegisteredDomain: h => h,
  });
  const r = await a.collect();
  assert.equal(r.forms.length, 1);
  assert.equal(r.pageTitle, '[redacted]');
  assert(a.limitations().some(x => /form/i.test(x)));
  assert(a.observations().some(x => x.kind === 'form_action_domain_comparison' && x.mismatch === true));
  assert.equal(a.observations().find(x => x.kind === 'form_action_domain_comparison').actionHost, 'other.test');
  r.forms[0].method = 'corrupt';
  assert.equal(a.result().forms[0].method, 'get');
  assert(!JSON.stringify([a.result(), a.observations(), a.limitations()]).includes('secret-sentinel'));
  a.stop(); a.stop();
});

test('total failure and frame cap are explicit', async () => {
  const broken = {evaluate: async () => {throw Error('private')}};
  const a = createDomAnalyzer(page(broken));
  assert.equal(await a.collect(), null);
  const b = createDomAnalyzer(page(frame([]), frame([])), {maxFrames:1});
  assert.equal(await b.collect(), null);
  assert(b.limitations().some(x => /frame/i.test(x)));
});

test('empty action uses document URL rather than a different base host', async () => {
  const a = createDomAnalyzer(page(frame([element('form')], 'Base', 'https://base.other.test/path/', 'https://example.test/current')));
  assert.equal((await a.collect()).forms[0].actionHost, 'example.test');
});
