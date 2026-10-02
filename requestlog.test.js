'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  hostFromUrl,
  registrableHost,
  isThirdParty,
  createStore,
  normalizeType,
  ingest,
  toList,
  stats,
  clear,
  hydrate,
} = require('./requestlog');

test('hostFromUrl only accepts http(s) and lowercases', () => {
  assert.equal(hostFromUrl('https://Example.COM:8443/a?b=1'), 'example.com');
  assert.equal(hostFromUrl('http://a.test/x'), 'a.test');
  assert.equal(hostFromUrl('cosy://security/'), '');
  assert.equal(hostFromUrl('not a url'), '');
  assert.equal(hostFromUrl(null), '');
});

test('registrableHost handles multi-part suffixes', () => {
  assert.equal(registrableHost('images.example.co.uk'), 'example.co.uk');
  assert.equal(registrableHost('a.b.example.com'), 'example.com');
  assert.equal(registrableHost('example.com'), 'example.com');
});

test('isThirdParty compares registrable hosts', () => {
  assert.equal(isThirdParty('www.example.com', 'img.example.com'), false);
  assert.equal(isThirdParty('example.co.uk', 'x.example.co.uk'), false);
  assert.equal(isThirdParty('example.com', 'tracker.evil.net'), true);
  assert.equal(isThirdParty('', 'x.test'), false);
});

test('normalizeType falls back to other', () => {
  assert.equal(normalizeType('script'), 'script');
  assert.equal(normalizeType('weird-new-type'), 'other');
  assert.equal(normalizeType(undefined), 'other');
});

test('ingest aggregates per host and records scheme/type/blocked', () => {
  const store = createStore();
  ingest(store, { url: 'https://a.test/app.js', resourceType: 'script' });
  ingest(store, { url: 'https://a.test/pixel', resourceType: 'image', blocked: true });
  ingest(store, { url: 'http://a.test/plain', resourceType: 'xhr' });
  ingest(store, { url: 'https://a.test/', resourceType: 'mainFrame', navigated: true });
  const rec = store.hosts.get('a.test');
  assert.equal(rec.requests, 4);
  assert.equal(rec.blocked, 1);
  assert.equal(rec.https, 3);
  assert.equal(rec.http, 1);
  assert.equal(rec.navigated, true);
  assert.equal(rec.byType.script, 1);
  assert.equal(rec.byType.image, 1);
});

test('ingest ignores bad entry', () => {
  const store = createStore();
  assert.equal(ingest(store, { url: 'cosy://x' }), null);
  assert.equal(ingest(null, { url: 'https://a.test' }), null);
  assert.equal(store.hosts.size, 0);
});

test('store evicts least-recently-active beyond cap', async () => {
  const store = createStore(3);
  ingest(store, { host: 'one.test', time: 100 });
  ingest(store, { host: 'two.test', time: 200 });
  ingest(store, { host: 'three.test', time: 300 });
  // touch one.test so two.test becomes the oldest
  ingest(store, { host: 'one.test', time: 400 });
  ingest(store, { host: 'four.test', time: 500 });
  assert.equal(store.hosts.has('two.test'), false);
  assert.equal(store.hosts.size, 3);
  assert.ok(store.hosts.has('one.test') && store.hosts.has('three.test') && store.hosts.has('four.test'));
});

test('toList marks third-party relative to page and sorts by recency', () => {
  const store = createStore();
  ingest(store, { host: 'self.example.com', resourceType: 'mainFrame', navigated: true, time: 100 });
  ingest(store, { host: 'cdn.third.net', resourceType: 'script', time: 200 });
  const list = toList(store, 'www.example.com');
  assert.equal(list[0].host, 'cdn.third.net');
  const self = list.find(r => r.host === 'self.example.com');
  const third = list.find(r => r.host === 'cdn.third.net');
  assert.equal(self.thirdParty, false);
  assert.equal(third.thirdParty, true);
  assert.ok(Array.isArray(third.types) && third.types[0].type === 'script');
});

test('stats reports totals and background/insecure hosts', () => {
  const store = createStore();
  ingest(store, { host: 'page.test', resourceType: 'mainFrame', navigated: true });
  ingest(store, { host: 'bg.test', resourceType: 'image' });
  ingest(store, { host: 'plain.test', scheme: 'http', resourceType: 'xhr' });
  const s = stats(store);
  assert.equal(s.hosts, 3);
  assert.equal(s.requests, 3);
  assert.equal(s.backgroundHosts, 2);
  assert.equal(s.insecureHosts, 1);
});

test('clear empties the store', () => {
  const store = createStore();
  ingest(store, { host: 'a.test' });
  clear(store);
  assert.equal(store.hosts.size, 0);
});

test('hydrate rebuilds valid records and rejects junk', () => {
  const store = hydrate([
    { host: 'ok.test', requests: 5, blocked: 2, https: 5, http: 0, navigated: true, byType: { script: 5 } },
    { host: '', requests: 9 },
    'garbage',
    null,
    { host: 'x.test', requests: 'notanumber', byType: 'bad' },
  ], 100);
  assert.equal(store.hosts.size, 2);
  const ok = store.hosts.get('ok.test');
  assert.equal(ok.requests, 5);
  assert.equal(ok.byType.script, 5);
  const x = store.hosts.get('x.test');
  assert.equal(x.requests, 0);
});

test('hydrate respects maxHosts cap', () => {
  const entries = [];
  for (let i = 0; i < 10; i++) entries.push({ host: `h${i}.test`, lastTime: i, requests: 1 });
  const store = hydrate(entries, 4);
  assert.equal(store.hosts.size, 4);
});
