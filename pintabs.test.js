'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const pinCore = require('./pintabs');
const {
  MAX_PINNED_TABS,
  CLOSE_ALL,
  CLOSE_OTHERS,
  CLOSE_LEFT,
  CLOSE_RIGHT,
  REJECT_NOT_STRING,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  REJECT_LIMIT,
  hasControlChar,
  sanitizePinId,
  sanitizePinUrl,
  sanitizeStoredPins,
  sanitizeStoredPinEntries,
  rehydratePinsByUrl,
  planBatchClose,
  describeReject,
  PinModel,
} = pinCore;

test('hasControlChar 识别 ASCII 控制字符', () => {
  assert.equal(hasControlChar('abc'), false);
  assert.equal(hasControlChar('标\u7b7e-1'), false);
  assert.equal(hasControlChar('a\x00b'), true);
  assert.equal(hasControlChar('x\x7F'), true);
  assert.equal(hasControlChar('line\n'), true);
});

test('sanitizePinId 类型 / 长度 / 控制字符校验', () => {
  assert.deepEqual(sanitizePinId('tab-1'), { ok: true, value: 'tab-1' });
  assert.equal(sanitizePinId(123).ok, false);
  assert.equal(sanitizePinId(null).reason, REJECT_NOT_STRING);
  assert.equal(sanitizePinId('').reason, REJECT_TOO_LONG);
  assert.equal(sanitizePinId('x'.repeat(MAX_PINNED_TABS + 999)).reason, REJECT_TOO_LONG);
  assert.equal(sanitizePinId('a\x01b').reason, REJECT_CONTROL);
});

test('sanitizePinUrl 拒绝非字符串 / 超长 / 控制字符', () => {
  assert.equal(sanitizePinUrl('https://example.com').ok, true);
  assert.equal(sanitizePinUrl('').ok, false);
  assert.equal(sanitizePinUrl({}).reason, REJECT_NOT_STRING);
  assert.equal(sanitizePinUrl('u'.repeat(5000)).reason, REJECT_TOO_LONG);
  assert.equal(sanitizePinUrl('https://x.com/\n').reason, REJECT_CONTROL);
});

test('PinModel 固定 / 取消 / 切换 / 幂等', () => {
  const m = new PinModel();
  assert.equal(m.count(), 0);
  assert.deepEqual(m.pin('a'), { ok: true, changed: true });
  assert.deepEqual(m.pin('a'), { ok: true, changed: false }); // 幂等
  assert.equal(m.isPinned('a'), true);
  assert.equal(m.isPinned('b'), false);

  m.pin('b');
  assert.deepEqual(m.ids(), ['a', 'b']);
  assert.deepEqual(m.unpin('a'), { ok: true, changed: true });
  assert.deepEqual(m.unpin('a'), { ok: true, changed: false }); // 幂等
  assert.deepEqual(m.ids(), ['b']);

  assert.equal(m.toggle('c').pinned, true);
  assert.equal(m.toggle('c').pinned, false);
  assert.equal(m.isPinned('c'), false);

  // 非法 id 不能进入模型
  assert.equal(m.pin(7).ok, false);
  assert.equal(m.pin('bad\x00').ok, false);
  assert.equal(m.count(), 1);
});

test('PinModel 受 MAX_PINNED_TABS 上界约束', () => {
  const m = new PinModel();
  for (let i = 0; i < MAX_PINNED_TABS; i++) {
    assert.equal(m.pin('id' + i).ok, true);
  }
  const over = m.pin('one-more');
  assert.equal(over.ok, false);
  assert.equal(over.reason, REJECT_LIMIT);
  assert.equal(m.count(), MAX_PINNED_TABS);
});

test('PinModel.arrange 稳定地把固定标签排到最前', () => {
  const m = new PinModel();
  m.pin('p2');
  m.pin('p1'); // 固定区顺序 p2,p1
  const out = m.arrange(['x', 'p1', 'y', 'p2', 'z']);
  // 固定区按模型顺序 p2,p1，非固定区保持 x,y,z
  assert.deepEqual(out, ['p2', 'p1', 'x', 'y', 'z']);
});

test('PinModel.arrange 去重且忽略非字符串', () => {
  const m = new PinModel();
  m.pin('a');
  const out = m.arrange(['a', 'a', 1, null, 'b', 'b']);
  assert.deepEqual(out, ['a', 'b']);
});

test('PinModel.serialize / applyStored 往返', () => {
  const m = new PinModel();
  m.pin('one');
  m.pin('two');
  const saved = m.serialize();
  const m2 = new PinModel();
  m2.applyStored(saved);
  assert.deepEqual(m2.ids(), ['one', 'two']);
  assert.equal(m2.isPinned('two'), true);
});

test('sanitizeStoredPins 去重 / 截断 / 丢弃脏元素', () => {
  const clean = sanitizeStoredPins(['a', 'b', 'a', 3, 'c\x00', 'c']);
  assert.deepEqual(clean, ['a', 'b', 'c']);
  assert.deepEqual(sanitizeStoredPins('nope'), []);
  assert.deepEqual(sanitizeStoredPins(null), []);

  const big = [];
  for (let i = 0; i < MAX_PINNED_TABS + 10; i++) big.push('t' + i);
  assert.equal(sanitizeStoredPins(big).length, MAX_PINNED_TABS);
});

test('sanitizeStoredPinEntries 净化 {id,url} 清单并按 URL 去重', () => {
  const input = [
    { id: 'x1', url: 'https://a.com' },
    { id: 'x2', url: 'https://a.com' },          // url 重复
    { id: 'x3', url: 'https://b.com' },
    { id: 7, url: 'https://c.com' },             // 非法 id 被剥但 url 保留
    { id: 'x5', url: 'bad\nurl' },               // 非法 url 整条丢弃
    null,
    'string',
    { id: 'x6' },                                // 缺 url 丢弃
  ];
  const out = sanitizeStoredPinEntries(input);
  assert.equal(out.length, 3);
  assert.equal(out[0].url, 'https://a.com');
  assert.equal(out[0].id, 'x1');
  assert.equal(out[1].url, 'https://b.com');
  assert.deepEqual(out[2], { url: 'https://c.com' });
});

test('rehydratePinsByUrl 用 URL 把固定状态映射到新标签 id', () => {
  const stored = [
    { id: 'old-1', url: 'https://mail.com' },
    { id: 'old-2', url: 'https://docs.com' },
    { id: 'old-3', url: 'https://gone.com' },   // 本次没恢复
  ];
  const current = [
    { id: 'new-9', url: 'https://newtab' },
    { id: 'new-2', url: 'https://docs.com' },
    { id: 'new-1', url: 'https://mail.com' },
  ];
  const pinned = rehydratePinsByUrl(stored, current);
  // 存储顺序 mail -> docs，映射到新 id；gone 被忽略
  assert.deepEqual(pinned, ['new-1', 'new-2']);
});

test('rehydratePinsByUrl 同 URL 多标签只固定第一个且不重复占用', () => {
  const stored = [
    { url: 'https://dup.com' },
    { url: 'https://dup.com' },
  ];
  const current = [
    { id: 'd1', url: 'https://dup.com' },
    { id: 'd2', url: 'https://dup.com' },
  ];
  assert.deepEqual(rehydratePinsByUrl(stored, current), ['d1']);
});

test('planBatchClose all 关闭全部非固定标签', () => {
  const tabs = [
    { id: 'p1', pinned: true },
    { id: 't1', pinned: false },
    { id: 't2', pinned: false },
  ];
  const r = planBatchClose(tabs, { mode: CLOSE_ALL });
  assert.deepEqual(r.closeIds, ['t1', 't2']);
  assert.deepEqual(r.keepIds, ['p1']);
});

test('planBatchClose others 保留锚点与全部固定标签', () => {
  const tabs = [
    { id: 'p1', pinned: true },
    { id: 't1', pinned: false },
    { id: 't2', pinned: false },
    { id: 't3', pinned: false },
  ];
  const r = planBatchClose(tabs, { mode: CLOSE_OTHERS, anchorId: 't2' });
  assert.deepEqual(r.closeIds, ['t1', 't3']);
  assert.deepEqual(r.keepIds, ['p1', 't2']);
});

test('planBatchClose 锚点是固定标签时它仍被保留', () => {
  const tabs = [
    { id: 'p1', pinned: true },
    { id: 't1', pinned: false },
  ];
  const r = planBatchClose(tabs, { mode: CLOSE_OTHERS, anchorId: 'p1' });
  assert.deepEqual(r.closeIds, ['t1']);
  assert.deepEqual(r.keepIds, ['p1']);
});

test('planBatchClose left/right 只关对应一侧且豁免固定', () => {
  const tabs = [
    { id: 'a', pinned: false },
    { id: 'p', pinned: true },
    { id: 'b', pinned: false },
    { id: 'c', pinned: false },
  ];
  const left = planBatchClose(tabs, { mode: CLOSE_LEFT, anchorId: 'b' });
  assert.deepEqual(left.closeIds, ['a']); // p 在左但固定，保留
  assert.deepEqual(left.keepIds, ['p', 'b', 'c']);

  const right = planBatchClose(tabs, { mode: CLOSE_RIGHT, anchorId: 'b' });
  assert.deepEqual(right.closeIds, ['c']);
  assert.deepEqual(right.keepIds, ['a', 'p', 'b']);
});

test('planBatchClose 非法 mode 与缺失锚点返回 null', () => {
  assert.equal(planBatchClose([], { mode: 'bogus' }), null);
  assert.equal(planBatchClose([{ id: 'a' }], { mode: CLOSE_LEFT }), null);
  assert.equal(planBatchClose([{ id: 'a' }], { mode: CLOSE_OTHERS, anchorId: 'x' }), null);
});

test('describeReject 覆盖全部原因码并对未知值兜底', () => {
  assert.ok(describeReject(REJECT_LIMIT).includes('上限'));
  assert.ok(describeReject(REJECT_CONTROL).includes('控制字符'));
  assert.equal(typeof describeReject('unknown'), 'string');
});
