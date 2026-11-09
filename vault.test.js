'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const V = require('./vault');

function randomKey() {
  return crypto.randomBytes(32);
}

function roundtrip(masterKey, kdf) {
  const c = V.createVault(masterKey, { kdf });
  assert.strictEqual(c.ok, true, JSON.stringify(c));
  const v = c.vault;
  const s1 = v.set('password', 'github', { user: 'alice', pass: 's3cret!' });
  assert.strictEqual(s1.ok, true, JSON.stringify(s1));
  const s2 = v.set('recovery', 'google 2fa', ['a1b2c3', 'd4e5f6']);
  assert.strictEqual(s2.ok, true);
  const s3 = v.set('note', 'ssh 密钥备注', '用于 CI 的部署密钥');
  assert.strictEqual(s3.ok, true);
  const g1 = v.get(s1.id);
  assert.strictEqual(g1.ok, true);
  assert.deepStrictEqual(g1.payload, { user: 'alice', pass: 's3cret!' });
  const g2 = v.get(s2.id);
  assert.deepStrictEqual(g2.payload, ['a1b2c3', 'd4e5f6']);
  const list = v.list();
  assert.strictEqual(list.ok, true);
  assert.strictEqual(list.entries.length, 3);
  return v.exportState().state;
}

test('createVault 拒绝弱主密钥', () => {
  for (const weak of [null, undefined, '', 'short', Buffer.alloc(8), 42, {}, []]) {
    const c = V.createVault(weak, {});
    assert.strictEqual(c.ok, false, String(weak));
    assert.strictEqual(c.reason, 'weak-master-key');
  }
});

test('HKDF 模式完整往返：写入→导出→重载→读取', () => {
  const key = randomKey();
  const state = roundtrip(key, V.KDF_HKDF);
  const data = JSON.stringify(state);
  const loaded = V.loadVault(data, key);
  assert.strictEqual(loaded.ok, true, JSON.stringify(loaded));
  assert.strictEqual(loaded.vault.locked(), false);
  const g = loaded.vault.get(Object.keys(state.entries)[0]);
  assert.strictEqual(g.ok, true);
});

test('PBKDF2 模式完整往返（自设主密码慢化）', () => {
  const key = Buffer.from('用户自定义主密码 2026', 'utf8');
  const state = roundtrip(key, V.KDF_PBKDF2);
  const loaded = V.loadVault(JSON.stringify(state), key);
  assert.strictEqual(loaded.ok, true);
  const ids = loaded.vault.list().entries.map((e) => e.id);
  assert.strictEqual(ids.length, 3);
});

test('错误主密钥无法解锁（auth-failed）', () => {
  const key = randomKey();
  const state = roundtrip(key, V.KDF_HKDF);
  const loaded = V.loadVault(JSON.stringify(state), randomKey());
  assert.strictEqual(loaded.ok, false);
  assert.strictEqual(loaded.reason, 'auth-failed');
});

test('密文被篡改后解密失败', () => {
  const key = randomKey();
  const c = V.createVault(key, {});
  const s = c.vault.set('note', '秘密', { body: 'do-not-touch' });
  assert.strictEqual(s.ok, true);
  const state = c.vault.exportState().state;
  const entry = state.entries[s.id];
  // 翻转密文一个字节。
  const enc = Buffer.from(entry.c, 'hex');
  enc[0] = enc[0] ^ 0xff;
  entry.c = enc.toString('hex');
  const v2 = new V.Vault(state, key);
  const g = v2.get(s.id);
  assert.strictEqual(g.ok, false);
  assert.strictEqual(g.reason, 'auth-failed');
});

test('lock 后读写被拒绝', () => {
  const key = randomKey();
  const c = V.createVault(key, {});
  c.vault.set('note', 'a', { x: 1 });
  c.vault.lock();
  assert.strictEqual(c.vault.locked(), true);
  assert.strictEqual(c.vault.get('any').reason, 'locked');
  assert.strictEqual(c.vault.set('note', 'b', {}).reason, 'locked');
  assert.strictEqual(c.vault.list().reason, 'locked');
  assert.strictEqual(c.vault.delete('any').reason, 'locked');
});

test('get/delete 对不存在条目返回 not-found', () => {
  const c = V.createVault(randomKey(), {});
  assert.strictEqual(c.vault.get('deadbeef').reason, 'not-found');
  assert.strictEqual(c.vault.delete('deadbeef').reason, 'not-found');
  assert.strictEqual(c.vault.get('').reason, 'bad-id');
  assert.strictEqual(c.vault.get(42).reason, 'bad-id');
});

test('种类与标签白名单收口', () => {
  const c = V.createVault(randomKey(), {});
  assert.strictEqual(c.vault.set('totp', 'x', {}).reason, 'bad-kind');
  assert.strictEqual(c.vault.set('PASSWORD', 'x', {}).reason, 'bad-kind');
  assert.strictEqual(c.vault.set('password', '', {}).reason, 'bad-label');
  assert.strictEqual(c.vault.set('password', '  ', {}).reason, 'bad-label');
  assert.strictEqual(c.vault.set('password', 'a\nb', {}).reason, 'bad-label');
  assert.strictEqual(c.vault.set('password', 'a\0b', {}).reason, 'bad-label');
  assert.strictEqual(c.vault.set('password', 'a'.repeat(300), {}).reason, 'bad-label');
  assert.strictEqual(c.vault.set('password', null, {}).reason, 'bad-label');
  assert.strictEqual(c.vault.set('password', 'ok', null).reason, 'bad-payload');
  assert.strictEqual(c.vault.set('password', 'ok', undefined).reason, 'bad-payload');
  const ok = c.vault.set('note', '正常标签', { v: 1 });
  assert.strictEqual(ok.ok, true);
});

test('update 按 id 原地改写并保持种类', () => {
  const c = V.createVault(randomKey(), {});
  const s = c.vault.set('password', 'old', { pass: 'old-pass' });
  const u = c.vault.update(s.id, 'password', 'new', { pass: 'new-pass' });
  assert.strictEqual(u.ok, true);
  const g = c.vault.get(s.id);
  assert.strictEqual(g.ok, true);
  assert.deepStrictEqual(g.payload, { pass: 'new-pass' });
  assert.strictEqual(c.vault.get(s.id).payload.pass, 'new-pass');
  assert.strictEqual(c.vault.update('nope', 'note', 'x', {}).reason, 'not-found');
  // update 后标签更新。
  assert.strictEqual(c.vault.list().entries[0].label, 'new');
});

test('载荷超限被拒绝', () => {
  const c = V.createVault(randomKey(), {});
  const big = { blob: 'x'.repeat(V.MAX_PAYLOAD_BYTES + 1) };
  assert.strictEqual(c.vault.set('note', 'big', big).reason, 'payload-too-large');
});

test('loadVault 对损坏状态 / 非对象返回明确错误', () => {
  assert.strictEqual(V.loadVault('not-json', randomKey()).reason, 'bad-state');
  assert.strictEqual(V.loadVault('{"format":"other"}', randomKey()).reason, 'bad-format');
  assert.strictEqual(V.loadVault('{"format":"cosy-vault-v1"}', 'short').reason, 'weak-master-key');
  assert.strictEqual(V.loadVault(null, randomKey()).reason, 'bad-state');
});

test('list 排序按更新时间倒序且不泄露密文', () => {
  const c = V.createVault(randomKey(), {});
  c.vault.set('note', 'first', { v: 1 });
  const older = Date.now() - 100000;
  const e0 = c.vault.list().entries[0];
  c.vault._state.entries[e0.id].u = older; // 人为改旧时间验证排序
  c.vault.set('note', 'second', { v: 2 });
  const list = c.vault.list();
  assert.strictEqual(list.entries[0].label, 'second');
  for (const e of list.entries) {
    assert.strictEqual(Object.keys(e).includes('c'), false);
    assert.strictEqual(Object.keys(e).includes('g'), false);
  }
});

test('导出状态可序列化且不含主密钥', () => {
  const key = randomKey();
  const c = V.createVault(key, {});
  c.vault.set('password', 'a', { p: 'x' });
  const state = c.vault.exportState().state;
  const json = JSON.stringify(state);
  assert.ok(json.length > 0);
  assert.strictEqual(json.includes(key.toString('hex')), false);
  assert.strictEqual(json.includes('x'), false); // 明文载荷不得出现在导出
});

test('rekey 切主密码后旧 key 失效、新 key 可读', () => {
  const key1 = randomKey();
  const c = V.createVault(key1, {});
  c.vault.set('password', 'a', { p: 'secret-1' });
  c.vault.set('note', 'b', { body: 'note-2' });
  const key2 = Buffer.from('新主密码 2026', 'utf8');
  const rr = c.vault.rekey(key2, { kdf: V.KDF_PBKDF2 });
  assert.strictEqual(rr.ok, true, JSON.stringify(rr));
  assert.strictEqual(rr.entries, 2);
  assert.strictEqual(rr.kdf, V.KDF_PBKDF2);
  // 旧 key 无法再开（rekey 已切换派生参数 + 重新包裹）。
  assert.strictEqual(V.loadVault(JSON.stringify(c.vault.exportState().state), key1).ok, false);
  const rel = V.loadVault(JSON.stringify(c.vault.exportState().state), key2);
  assert.strictEqual(rel.ok, true);
  const g = rel.vault.get(Object.keys(rel.vault.exportState().state.entries)[0]);
  assert.strictEqual(g.ok, true);
  // 载荷可读且未被破坏。
  const ids = rel.vault.list().entries.map((e) => e.id);
  assert.strictEqual(ids.length, 2);
});

test('rekey 拒绝弱新密钥且失败时状态不变', () => {
  const c = V.createVault(randomKey(), {});
  c.vault.set('note', 'a', { x: 1 });
  const before = JSON.stringify(c.vault.exportState().state);
  const rr = c.vault.rekey('weak', {});
  assert.strictEqual(rr.ok, false);
  assert.strictEqual(rr.reason, 'weak-master-key');
  assert.strictEqual(JSON.stringify(c.vault.exportState().state), before);
  // 锁定后 rekey 被拒。
  c.vault.lock();
  assert.strictEqual(c.vault.rekey(randomKey(), {}).reason, 'locked');
});

test('mergeFromState 合并同 key 备份（id 冲突跳过）', () => {
  const key = randomKey();
  const a = V.createVault(key, {});
  const s1 = a.vault.set('password', 'from-a', { p: 'x' });
  a.vault.set('note', 'shared-label', { v: 1 });
  const backupState = a.vault.exportState().state;
  const b = V.createVault(key, {});
  b.vault.set('note', 'from-b', { v: 2 });
  const mr = b.vault.mergeFromState(backupState);
  assert.strictEqual(mr.ok, true, JSON.stringify(mr));
  assert.ok(mr.merged >= 2); // from-a 两条都被合入
  const g = b.vault.get(s1.id);
  assert.strictEqual(g.ok, true);
  assert.deepStrictEqual(g.payload, { p: 'x' });
  // 再次合并同一备份：全部 id 冲突 → merged 0、skipped = 备份条目数。
  const mr2 = b.vault.mergeFromState(backupState);
  assert.strictEqual(mr2.ok, true);
  assert.strictEqual(mr2.merged, 0);
  assert.ok(mr2.skipped >= 2);
});

test('mergeFromState 拒绝坏格式 / 错 key / 超量备份', () => {
  const key = randomKey();
  const a = V.createVault(key, {});
  a.vault.set('note', 'x', { v: 1 });
  const good = a.vault.exportState().state;
  const b = V.createVault(key, {});
  assert.strictEqual(b.vault.mergeFromState(null).reason, 'bad-format');
  assert.strictEqual(b.vault.mergeFromState({ format: 'other' }).reason, 'bad-format');
  assert.strictEqual(b.vault.mergeFromState([1, 2]).reason, 'bad-format');
  // 错 key 备份：用另一个 key 造一份同格式密文。
  const other = V.createVault(randomKey(), {});
  other.vault.set('note', 'y', { v: 9 });
  assert.strictEqual(b.vault.mergeFromState(other.vault.exportState().state).reason, 'auth-failed');
  // 超量：空备份合并返回 ok。
  assert.strictEqual(b.vault.mergeFromState({ format: V.VAULT_FORMAT, kdf: 'hkdf', entries: {} }).ok, true);
  // 锁定后拒绝。
  b.vault.lock();
  assert.strictEqual(b.vault.mergeFromState(good).reason, 'locked');
});
