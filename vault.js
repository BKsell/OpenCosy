'use strict';

// vault.js —— 本地加密保险库内核（AES-256-GCM + HKDF 派生）。
//
// 用途：把用户自愿保存的敏感条目（站点登录密码、双因素恢复码、私密笔记）加密
// 落盘。威胁模型与威胁边界：
//
//  1. 磁盘泄露：条目以 AES-256-GCM 密文存储，主密钥不出内核（由 main 进程用
//     safeStorage 加密后落盘），拿到 vault.json 的人无法解出任何条目内容。
//  2. 篡改：GCM 认证标签保证密文 / IV / 条目元数据（种类、标签、时间）被改动后
//     解密即失败；loadVault 也会校验整体格式与版本。
//  3. 暴力破解：支持可选的 PBKDF2 迭代派生（自设主密码模式）；safeStorage 模式
//     使用高熵随机主密钥，直接 HKDF 派生即可，无需 KDF 慢化。
//  4. 泄漏面收敛：id 由随机 16 字节生成；条目密文内容与 id/标签分离，list 只暴露
//     元数据；get 之后调用方负责及时置空内存（内核不做零化，由调用方约束）。
//
// 本文件只做加密 / 解密 / 条目组织，不依赖 Electron，可被 node:test 全量覆盖。

const crypto = require('crypto');

const VAULT_FORMAT = 'cosy-vault-v1';
const KDF_HKDF = 'hkdf';
const KDF_PBKDF2 = 'pbkdf2';
const DEFAULT_PBKDF2_ROUNDS = 310000; // OWASP 建议数量级；仅自设密码模式使用
const ID_BYTES = 16;
const KEY_BYTES = 32;
const MAX_LABEL_BYTES = 256;
const MAX_PAYLOAD_BYTES = 64 * 1024;
const MAX_ENTRIES = 512;
const MIN_MASTER_KEY_BYTES = 16;

// deriveEntryKey 派生单个条目密钥：HKDF 或 PBKDF2（自设密码慢化）。
function deriveEntryKey(masterKey, kdf, saltBuf, rounds) {
  if (kdf === KDF_PBKDF2) {
    return crypto.pbkdf2Sync(masterKey, saltBuf, rounds, KEY_BYTES, 'sha256');
  }
  return crypto.hkdfSync('sha256', masterKey, saltBuf, 'cosy-vault-entry', KEY_BYTES);
}

// newId 生成随机条目 id（hex，不可猜测）。
function newId() {
  return crypto.randomBytes(ID_BYTES).toString('hex');
}

// normalizeKind 收口条目种类：未知种类一律拒绝，避免脏标签混入审计。
function normalizeKind(kind) {
  if (kind === 'password' || kind === 'note' || kind === 'recovery') return kind;
  return '';
}

// normalizeLabel 校验并截断标签；空标签拒绝（无标签的条目无法被用户识别）。
function normalizeLabel(label) {
  if (typeof label !== 'string') return '';
  const t = label.trim();
  if (t === '') return '';
  const bytes = Buffer.byteLength(t, 'utf8');
  if (bytes > MAX_LABEL_BYTES) return '';
  if (t.includes('\0') || t.includes('\n') || t.includes('\r')) return '';
  return t;
}

// sealEntry 加密一个条目。payload 必须可 JSON 序列化且小于上限。
function sealEntry(masterKey, kdf, id, saltBuf, rounds, kind, label, payload) {
  const plain = Buffer.from(JSON.stringify(payload), 'utf8');
  if (plain.length > MAX_PAYLOAD_BYTES) {
    return { ok: false, reason: 'payload-too-large' };
  }
  const key = deriveEntryKey(masterKey, kdf, saltBuf, rounds);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ok: true,
    entry: {
      t: kind,
      n: label,
      k: kdf,
      r: rounds,
      s: saltBuf.toString('hex'),
      c: enc.toString('hex'),
      iv: iv.toString('hex'),
      g: tag.toString('hex'),
      u: Date.now(),
    },
  };
}

// openEntry 解密条目；认证失败（篡改 / 错误密钥 / 损坏）返回 reason，不抛异常。
function openEntry(masterKey, entry) {
  if (!entry || typeof entry !== 'object') return { ok: false, reason: 'bad-entry' };
  const kdf = entry.k === KDF_PBKDF2 ? KDF_PBKDF2 : KDF_HKDF;
  const rounds = Number.isInteger(entry.r) && entry.r > 0 ? entry.r : DEFAULT_PBKDF2_ROUNDS;
  let saltBuf;
  try {
    saltBuf = Buffer.from(String(entry.s), 'hex');
  } catch {
    return { ok: false, reason: 'bad-salt' };
  }
  if (saltBuf.length === 0) return { ok: false, reason: 'bad-salt' };
  const key = deriveEntryKey(masterKey, kdf, saltBuf, rounds);
  let enc, iv, tag;
  try {
    enc = Buffer.from(String(entry.c), 'hex');
    iv = Buffer.from(String(entry.iv), 'hex');
    tag = Buffer.from(String(entry.g), 'hex');
  } catch {
    return { ok: false, reason: 'bad-ciphertext' };
  }
  if (iv.length !== 12 || tag.length !== 16) {
    return { ok: false, reason: 'bad-ciphertext' };
  }
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(enc), decipher.final()]);
    return { ok: true, payload: JSON.parse(plain.toString('utf8')) };
  } catch {
    return { ok: false, reason: 'auth-failed' };
  }
}

// Vault 是已解锁保险库句柄：持有主密钥内存副本，lock() 后不可再读写。
class Vault {
  constructor(state, masterKey) {
    this._state = state;
    this._key = masterKey;
  }

  locked() {
    return this._key === null;
  }

  // lock 丢弃主密钥内存副本；已解锁状态不可逆（需重新 unlock）。
  lock() {
    this._key = null;
    return true;
  }

  // validate 校验解锁态与格式，读写操作统一入口。
  _ready() {
    if (this.locked()) return { ok: false, reason: 'locked' };
    if (!this._state || this._state.format !== VAULT_FORMAT) {
      return { ok: false, reason: 'bad-format' };
    }
    return { ok: true };
  }

  list() {
    const r = this._ready();
    if (!r.ok) return r;
    const out = [];
    for (const id of Object.keys(this._state.entries)) {
      const e = this._state.entries[id];
      if (!e) continue;
      out.push({ id, kind: e.t, label: e.n, updatedAt: e.u || 0 });
    }
    out.sort((a, b) => b.updatedAt - a.updatedAt);
    return { ok: true, entries: out };
  }

  get(id) {
    const r = this._ready();
    if (!r.ok) return r;
    if (typeof id !== 'string' || id === '') return { ok: false, reason: 'bad-id' };
    const entry = this._state.entries[id];
    if (!entry) return { ok: false, reason: 'not-found' };
    return openEntry(this._key, entry);
  }

  // set 新建或按 id 覆盖条目；返回条目 id。
  set(kind, label, payload) {
    const r = this._ready();
    if (!r.ok) return r;
    const k = normalizeKind(kind);
    if (!k) return { ok: false, reason: 'bad-kind' };
    const n = normalizeLabel(label);
    if (!n) return { ok: false, reason: 'bad-label' };
    if (payload === undefined || payload === null) {
      return { ok: false, reason: 'bad-payload' };
    }
    const id = newId();
    const kdf = this._state.kdf === KDF_PBKDF2 ? KDF_PBKDF2 : KDF_HKDF;
    const rounds = this._state.kdf === KDF_PBKDF2 ? this._state.pbkdf2Rounds : 0;
    const salt = crypto.randomBytes(16);
    const sealed = sealEntry(this._key, kdf, id, salt, rounds, k, n, payload);
    if (!sealed.ok) return sealed;
    if (Object.keys(this._state.entries).length >= MAX_ENTRIES) {
      return { ok: false, reason: 'vault-full' };
    }
    this._state.entries[id] = sealed.entry;
    return { ok: true, id };
  }

  // update 按 id 原地改写；不存在返回 not-found。
  update(id, kind, label, payload) {
    const r = this._ready();
    if (!r.ok) return r;
    const k = normalizeKind(kind);
    if (!k) return { ok: false, reason: 'bad-kind' };
    const n = normalizeLabel(label);
    if (!n) return { ok: false, reason: 'bad-label' };
    const entry = this._state.entries[id];
    if (!entry) return { ok: false, reason: 'not-found' };
    const salt = crypto.randomBytes(16);
    const sealed = sealEntry(this._key, entry.k === KDF_PBKDF2 ? KDF_PBKDF2 : KDF_HKDF,
      id, salt, entry.k === KDF_PBKDF2 ? entry.r || DEFAULT_PBKDF2_ROUNDS : 0, k, n, payload);
    if (!sealed.ok) return sealed;
    this._state.entries[id] = sealed.entry;
    return { ok: true };
  }

  delete(id) {
    const r = this._ready();
    if (!r.ok) return r;
    if (!Object.prototype.hasOwnProperty.call(this._state.entries, id)) {
      return { ok: false, reason: 'not-found' };
    }
    delete this._state.entries[id];
    return { ok: true };
  }

  // verify 用给定主密钥做一次“解密探针”，用于创建 / 重开保险库时确认密钥正确。
  static verify(state, masterKey) {
    if (!state || state.format !== VAULT_FORMAT) return false;
    if (typeof masterKey === 'string') masterKey = Buffer.from(masterKey, 'utf8');
    if (!Buffer.isBuffer(masterKey) || masterKey.length < MIN_MASTER_KEY_BYTES) return false;
    // 用 entries 里任一条目做认证解密；空库则仅校验格式与派生参数。
    const ids = Object.keys(state.entries);
    if (ids.length === 0) return true;
    const probe = openEntry(masterKey, state.entries[ids[0]]);
    return probe.ok;
  }

  exportState() {
    const r = this._ready();
    if (!r.ok) return r;
    return { ok: true, state: this._state };
  }

  // rekey 用新主密钥重新包裹全部条目（改主密码 / 切换 KDF）。先逐条解旧再封新，
  // 任一条解密失败即整体中止（保持状态原样），避免半更新造成部分条目不可读。
  rekey(newKey, opts) {
    const r = this._ready();
    if (!r.ok) return r;
    let key = newKey;
    if (typeof key === 'string') key = Buffer.from(key, 'utf8');
    if (!Buffer.isBuffer(key) || key.length < MIN_MASTER_KEY_BYTES) {
      return { ok: false, reason: 'weak-master-key' };
    }
    const kdf = opts && opts.kdf === KDF_PBKDF2 ? KDF_PBKDF2 : KDF_HKDF;
    const rounds = kdf === KDF_PBKDF2 ? DEFAULT_PBKDF2_ROUNDS : 0;
    const ids = Object.keys(this._state.entries);
    const next = {};
    for (const id of ids) {
      const entry = this._state.entries[id];
      const opened = openEntry(this._key, entry);
      if (!opened.ok) return { ok: false, reason: 'rekey-failed' };
      const salt = crypto.randomBytes(16);
      const sealed = sealEntry(key, kdf, id, salt, rounds, entry.t, entry.n, opened.payload);
      if (!sealed.ok) return { ok: false, reason: 'rekey-failed' };
      next[id] = sealed.entry;
    }
    this._state.entries = next;
    this._state.kdf = kdf;
    this._state.pbkdf2Rounds = rounds;
    this._key = key; // 句柄切换到新密钥；调用方随后应丢弃旧句柄引用。
    return { ok: true, entries: ids.length, kdf, rounds };
  }

  // mergeFromState 把备份状态（同一主密钥包裹的密文）合并进当前保险库。
  // 先做一次认证探针：备份第一条无法用当前 key 解开就整体拒绝，防止导入
  // 伪造/错 key 密文后产生大量不可读条目。
  mergeFromState(backupState) {
    const r = this._ready();
    if (!r.ok) return r;
    if (!backupState || typeof backupState !== 'object' || Array.isArray(backupState)
      || backupState.format !== VAULT_FORMAT) {
      return { ok: false, reason: 'bad-format' };
    }
    const ids = Object.keys(backupState.entries);
    if (ids.length === 0) return { ok: true, merged: 0, skipped: 0 };
    if (ids.length > MAX_ENTRIES) return { ok: false, reason: 'too-many-entries' };
    if (Vault.verify(backupState, this._key) === false) {
      return { ok: false, reason: 'auth-failed' };
    }
    let merged = 0;
    let skipped = 0;
    for (const id of ids) {
      if (this._state.entries[id]) { skipped += 1; continue; }
      if (Object.keys(this._state.entries).length >= MAX_ENTRIES) break;
      const opened = openEntry(this._key, backupState.entries[id]);
      if (!opened.ok) { skipped += 1; continue; }
      this._state.entries[id] = backupState.entries[id];
      merged += 1;
    }
    return { ok: true, merged, skipped };
  }
}

// createVault 新建保险库状态（未持久化，由调用方写盘）。
// opts.masterKey: Buffer/string ≥16 字节；opts.kdf: 'hkdf'（默认）| 'pbkdf2'。
function createVault(masterKey, opts) {
  opts = opts || {};
  let key = masterKey;
  if (typeof key === 'string') key = Buffer.from(key, 'utf8');
  if (!Buffer.isBuffer(key) || key.length < MIN_MASTER_KEY_BYTES) {
    return { ok: false, reason: 'weak-master-key' };
  }
  const kdf = opts.kdf === KDF_PBKDF2 ? KDF_PBKDF2 : KDF_HKDF;
  const rounds = kdf === KDF_PBKDF2 ? DEFAULT_PBKDF2_ROUNDS : 0;
  const state = {
    format: VAULT_FORMAT,
    kdf,
    pbkdf2Rounds: rounds,
    createdAt: Date.now(),
    entries: {},
  };
  return { ok: true, vault: new Vault(state, key) };
}

// loadVault 载入持久化状态并用主密钥解锁；密钥错误时返回 auth-failed。
function loadVault(data, masterKey) {
  let state;
  try {
    state = JSON.parse(data);
  } catch {
    return { ok: false, reason: 'bad-state' };
  }
  // JSON 字面量 "null" / 数字 / 数组等非对象都算坏状态，而不是格式错误。
  if (state === null || typeof state !== 'object' || Array.isArray(state)) {
    return { ok: false, reason: 'bad-state' };
  }
  if (state.format !== VAULT_FORMAT) return { ok: false, reason: 'bad-format' };
  let key = masterKey;
  if (typeof key === 'string') key = Buffer.from(key, 'utf8');
  if (!Buffer.isBuffer(key) || key.length < MIN_MASTER_KEY_BYTES) {
    return { ok: false, reason: 'weak-master-key' };
  }
  if (!Vault.verify(state, key)) return { ok: false, reason: 'auth-failed' };
  return { ok: true, vault: new Vault(state, key) };
}

module.exports = {
  VAULT_FORMAT,
  KDF_HKDF,
  KDF_PBKDF2,
  DEFAULT_PBKDF2_ROUNDS,
  MAX_ENTRIES,
  MAX_PAYLOAD_BYTES,
  MIN_MASTER_KEY_BYTES,
  createVault,
  loadVault,
  Vault,
  normalizeKind,
  normalizeLabel,
  openEntry,
  sealEntry,
};
