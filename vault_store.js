const crypto = require('crypto');
const { VAULT_FORMAT, KDF_HKDF, KDF_PBKDF2, DEFAULT_PBKDF2_ROUNDS, ID_BYTES, KEY_BYTES, MAX_LABEL_BYTES, MAX_PAYLOAD_BYTES, MAX_ENTRIES, MIN_MASTER_KEY_BYTES, deriveEntryKey, newId, normalizeKind, normalizeLabel, sealEntry, openEntry } = require('./vaultentry');


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

module.exports = {
  Vault,
};
