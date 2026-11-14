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
const SALT_BYTES = 16;
const MAX_PBKDF2_ROUNDS = 1000000;
const MIN_PBKDF2_ROUNDS = 100000;

// deriveEntryKey 派生单个条目密钥：HKDF 或 PBKDF2（自设密码慢化）。
function normalizeRounds(rounds) {
  const n = Number(rounds);
  if (!Number.isInteger(n) || n <= 0 || n > MAX_PBKDF2_ROUNDS) return 0;
  return n;
}

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

// metadataAad 把明文元数据绑进 GCM 认证范围，篡改种类/标签/轮数会让解封直接失败。
function metadataAad(kind, label, kdf, rounds, updated) {
  return Buffer.from(JSON.stringify([kind, label, kdf, rounds, updated]), 'utf8');
}

// sealEntry 加密一个条目。payload 必须可 JSON 序列化且小于上限。
function sealEntry(masterKey, kdf, id, saltBuf, rounds, kind, label, payload) {
  if (kdf === KDF_PBKDF2 && normalizeRounds(rounds) < MIN_PBKDF2_ROUNDS) {
    return { ok: false, reason: 'bad-rounds' };
  }
  const plain = Buffer.from(JSON.stringify(payload), 'utf8');
  if (plain.length > MAX_PAYLOAD_BYTES) {
    return { ok: false, reason: 'payload-too-large' };
  }
  const key = deriveEntryKey(masterKey, kdf, saltBuf, rounds);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const updated = Date.now();
  cipher.setAAD(metadataAad(kind, label, kdf, rounds, updated));
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
      u: updated,
      a: 1,
    },
  };
}

// openEntry 解密条目；认证失败（篡改 / 错误密钥 / 损坏）返回 reason，不抛异常。
function openEntry(masterKey, entry) {
  if (!entry || typeof entry !== 'object') return { ok: false, reason: 'bad-entry' };
  const kdf = entry.k === KDF_PBKDF2 ? KDF_PBKDF2 : KDF_HKDF;
  const rounds = kdf === KDF_PBKDF2
    ? normalizeRounds(entry.r === undefined ? DEFAULT_PBKDF2_ROUNDS : entry.r)
    : DEFAULT_PBKDF2_ROUNDS;
  if (rounds === 0) return { ok: false, reason: 'bad-rounds' };
  let saltBuf;
  try {
    saltBuf = Buffer.from(String(entry.s), 'hex');
  } catch {
    return { ok: false, reason: 'bad-salt' };
  }
  if (saltBuf.length !== SALT_BYTES) return { ok: false, reason: 'bad-salt' };
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
  if (enc.length > MAX_PAYLOAD_BYTES) return { ok: false, reason: 'bad-ciphertext' };
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    if (entry.a === 1) {
      const kind = normalizeKind(entry.t);
      const label = normalizeLabel(entry.n);
      if (kind === '' || label === '') return { ok: false, reason: 'bad-entry' };
      const updated = Number.isInteger(entry.u) ? entry.u : -1;
      const aadRounds = kdf === KDF_PBKDF2 ? rounds : (Number.isInteger(entry.r) ? entry.r : 0);
      decipher.setAAD(metadataAad(kind, label, kdf, aadRounds, updated));
    }
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(enc), decipher.final()]);
    return { ok: true, payload: JSON.parse(plain.toString('utf8')) };
  } catch {
    return { ok: false, reason: 'auth-failed' };
  }
}

// Vault 是已解锁保险库句柄：持有主密钥内存副本，lock() 后不可再读写。

module.exports = {
  VAULT_FORMAT,
  KDF_HKDF,
  KDF_PBKDF2,
  DEFAULT_PBKDF2_ROUNDS,
  ID_BYTES,
  KEY_BYTES,
  MAX_LABEL_BYTES,
  MAX_PAYLOAD_BYTES,
  MAX_ENTRIES,
  MIN_MASTER_KEY_BYTES,
  SALT_BYTES,
  MAX_PBKDF2_ROUNDS,
  MIN_PBKDF2_ROUNDS,
  normalizeRounds,
  deriveEntryKey,
  newId,
  normalizeKind,
  normalizeLabel,
  sealEntry,
  openEntry,
};
