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

const { VAULT_FORMAT, KDF_HKDF, KDF_PBKDF2, DEFAULT_PBKDF2_ROUNDS, ID_BYTES, KEY_BYTES, MAX_LABEL_BYTES, MAX_PAYLOAD_BYTES, MAX_ENTRIES, MIN_MASTER_KEY_BYTES, deriveEntryKey, newId, normalizeKind, normalizeLabel, sealEntry, openEntry } = require('./vaultentry_core');

const { Vault } = require('./vault_store_core');
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
