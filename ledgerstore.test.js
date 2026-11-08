'use strict';

// ledgerstore.test.js —— 统一持久化内核测试：缺失回退、损坏回退、超大拦截、
// 往返一致、原子写不留 tmp、createJSONStore 的懒加载/只加载一次/防抖/flush。

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  DEFAULT_MAX_BYTES,
  readJSONStore,
  atomicWrite,
  writeJSONStore,
  createJSONStore,
} = require('./ledgerstore');

function tempFile(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledgerstore-'));
  return path.join(dir, name);
}

test('readJSONStore: 文件缺失时返回 fallback', () => {
  const p = tempFile('missing.json');
  assert.deepStrictEqual(readJSONStore(p, { a: 1 }), { a: 1 });
  assert.deepStrictEqual(readJSONStore(p, null), null);
});

test('readJSONStore: 正常往返', () => {
  const p = tempFile('ok.json');
  writeJSONStore(p, { version: 1, rows: [1, 2, 3] });
  assert.deepStrictEqual(readJSONStore(p, {}), { version: 1, rows: [1, 2, 3] });
});

test('readJSONStore: 损坏 JSON 默认回落并回调 onCorrupt', () => {
  const p = tempFile('bad.json');
  fs.writeFileSync(p, '{broken', 'utf8');
  const corrupt = [];
  assert.deepStrictEqual(
    readJSONStore(p, { fallback: true }, { onCorrupt: (e) => corrupt.push(e) }),
    { fallback: true }
  );
  assert.strictEqual(corrupt.length, 1);
});

test('readJSONStore: 损坏 JSON 在 throwOnError 时抛出', () => {
  const p = tempFile('bad2.json');
  fs.writeFileSync(p, 'not-json', 'utf8');
  assert.throws(() => readJSONStore(p, {}, { throwOnError: true }), SyntaxError);
});

test('readJSONStore: 超过上限的台账按损坏回落，不整读', () => {
  const p = tempFile('huge.json');
  fs.writeFileSync(p, Buffer.alloc(1024, 0x7b), 'utf8');
  const corrupt = [];
  const got = readJSONStore(p, 'FB', { maxBytes: 64, onCorrupt: (e) => corrupt.push(e) });
  assert.strictEqual(got, 'FB');
  assert.strictEqual(corrupt.length, 1);
  assert.strictEqual(corrupt[0].code, 'LEDGER_TOO_LARGE');
});

test('readJSONStore: 非法 maxBytes 回落到默认上限', () => {
  const p = tempFile('small.json');
  writeJSONStore(p, { x: 1 });
  // 传 0 不应被当成“读 0 字节”，正常文件仍应读出来。
  assert.deepStrictEqual(readJSONStore(p, null, { maxBytes: 0 }), { x: 1 });
  assert.ok(DEFAULT_MAX_BYTES > 0);
});

test('atomicWrite: 覆盖写且不留临时文件', () => {
  const p = tempFile('atomic.txt');
  atomicWrite(p, 'first');
  atomicWrite(p, 'second');
  assert.strictEqual(fs.readFileSync(p, 'utf8'), 'second');
  const leftovers = fs.readdirSync(path.dirname(p)).filter((n) => n.endsWith('.tmp'));
  assert.deepStrictEqual(leftovers, []);
});

test('atomicWrite: 写失败不破坏同目录既有文件且不留 tmp', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledgerstore-fail-'));
  const keep = path.join(dir, 'keep.txt');
  atomicWrite(keep, 'original');
  // 把目标文件的“父目录”占成一个普通文件：在其下 mkdir / 打开必然失败，
  // 这是不依赖文件权限位、跨平台稳定的失败注入。
  const blocker = path.join(dir, 'blocker');
  fs.writeFileSync(blocker, 'x');
  const target = path.join(blocker, 'nested.txt');
  assert.throws(() => atomicWrite(target, 'data'));
  assert.strictEqual(fs.readFileSync(keep, 'utf8'), 'original');
  const leftovers = fs.readdirSync(dir).filter((n) => n.endsWith('.tmp'));
  assert.deepStrictEqual(leftovers, []);
});

test('writeJSONStore: pretty 模式含缩进', () => {
  const p = tempFile('pretty.json');
  writeJSONStore(p, { a: 1 }, { pretty: true });
  const raw = fs.readFileSync(p, 'utf8');
  assert.ok(raw.includes('\n  "a": 1'), 'pretty 应包含换行缩进');
});

test('createJSONStore: 懒加载且只 hydrate 一次', () => {
  const p = tempFile('ledger.json');
  writeJSONStore(p, { version: 1, rows: [{ host: 'a' }, { host: 'b' }] });
  const map = new Map();
  let hydrateCount = 0;
  const store = createJSONStore({
    file: p,
    delay: 20,
    hydrate(data) {
      hydrateCount += 1;
      for (const r of data.rows || []) map.set(r.host, r);
    },
    serialize() { return { version: 1, rows: [...map.values()] }; },
  });
  assert.strictEqual(store.loaded, false);
  store.ensureLoaded();
  store.ensureLoaded();
  assert.strictEqual(hydrateCount, 1);
  assert.strictEqual(map.size, 2);
  assert.strictEqual(store.loaded, true);
});

test('createJSONStore: 缺失文件 hydrate 不被调用，flush 仍可写出', (_, done) => {
  const p = tempFile('fresh.json');
  let hydrated = 0;
  const items = [];
  const store = createJSONStore({
    file: p,
    delay: 15,
    hydrate() { hydrated += 1; },
    serialize() { return { version: 1, items }; },
  });
  store.ensureLoaded();
  assert.strictEqual(hydrated, 0);
  items.push('x');
  store.schedule();
  setTimeout(() => {
    assert.deepStrictEqual(readJSONStore(p, null), { version: 1, items: ['x'] });
    done();
  }, 60);
});

test('createJSONStore: flush 立即落盘并返回成功标志', () => {
  const p = tempFile('flush.json');
  const store = createJSONStore({
    file: p,
    hydrate() {},
    serialize() { return { ok: true }; },
  });
  assert.strictEqual(store.flush(), true);
  assert.deepStrictEqual(readJSONStore(p, null), { ok: true });
});

test('createJSONStore: serialize 抛错时 flush 返回 false', () => {
  const p = tempFile('boom.json');
  const store = createJSONStore({
    file: p,
    hydrate() {},
    serialize() { throw new Error('boom'); },
  });
  assert.strictEqual(store.flush(), false);
});

test('createJSONStore: 缺少 file 直接报错', () => {
  assert.throws(() => createJSONStore({}), /file/);
});
