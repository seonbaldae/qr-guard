const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createObserver } = require('../observer.cjs');

test('observer cancels HTTP, blob and data downloads without retaining URL secrets', () => {
  const page = new EventEmitter();
  const context = new EventEmitter();
  const observer = createObserver(page, context, 'download', { observeNetwork: false, observeNavigation: false });
  assert.equal(page.listenerCount('request'), 0);
  assert.equal(page.listenerCount('response'), 0);
  let cancellations = 0;
  for (const url of [
    'data:text/plain,secret-sentinel',
    'blob:https://example.test/secret-sentinel',
    'https://user:secret-sentinel@example.test/token/secret-sentinel?token=secret-sentinel',
  ]) {
    assert.doesNotThrow(() => page.emit('download', {
      url: () => url, cancel: async () => { cancellations++; },
    }));
  }
  assert.equal(cancellations, 3);
  assert.deepEqual(observer.result().evidence.map(x => x.data.host), [null, null, 'example.test']);
  assert.equal(JSON.stringify(observer.result()).includes('secret-sentinel'), false);
  observer.stop();
  assert.equal(page.listenerCount('download'), 0);
  assert.equal(context.listenerCount('page'), 0);
});
