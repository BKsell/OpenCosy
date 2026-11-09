const { KNOWN_AUTH_SCHEMES, DEFAULT_MAX_PROMPTS_IN_WINDOW, DEFAULT_PROMPT_WINDOW_MS, DEFAULT_PROMPT_COOLDOWN_MS, AUTH_PROMPT_TIMEOUT_MS, MAX_PENDING_PROMPTS, MAX_REALM_CHARS, MAX_HOST_CHARS, MAX_USERNAME_CHARS, MAX_PASSWORD_CHARS, clampText, lowerTrim, parseHttpUrl, authHostKey, normalizeScheme, classifyServerAuth, classifyProxyAuth, AuthPromptRateLimiter } = require('./netauthcert');

'use strict';

// netauthguard.js —— 网络身份认证治理纯逻辑内核（不依赖 Electron）。
//
// 现代浏览器对两类“操作系统/网络层”身份事件有自己的安全策略，而 Electron
// 默认把它们交给原生对话框、甚至静默复用当前系统登录凭据：
//
//   1) HTTP 401/407（Basic/Digest/NTLM/Negotiate）。
//      - 子框架 / 跨源图片脚本触发的 401 常被用来“凭据探测”：攻击者页面塞
//        一个 <img src="http://intranet/">，浏览器若自动带 NTLM 凭据，就能
//        探内网主机是否存活、当前用户是谁。现代浏览器只对顶层主框架的 401
//        弹框，子框架一律静默失败。
//      - 恶意站点还能对一堆主机连续返回 401 制造“认证弹框轰炸”，把用户点烦
//        后随手输入口令，或直接用弹出框做 UI 红鲱鱼。必须按主机做限流。
//      - NTLM/Negotiate 绝不能静默用当前操作系统身份，必须显式让用户知情。
//
//   2) TLS 客户端证书（select-client-certificate）。
//      多证书环境下若自动选一张发给服务器，等于把“我有某 CA 签发的身份”
//      这一隐私主动泄露给任意站点。现代浏览器默认不自动发送，必须用户明确
//      选择。本模块在没有“用户为该主机明确记住的指纹”时永远返回不选择。
//
// main.js 只负责接 Electron 事件与 IPC；所有“该不该弹、按谁限流、证书能不能
// 自动发”的判定集中在本文件，用 node:test 做表驱动单测。

// 已知的 Web 身份认证方案。unknown 方案不弹框（fail-closed），避免出现我们
// 不了解语义的新方案时把凭据交给它。
function normalizeCertFingerprint(value) {
  if (typeof value !== 'string') return '';
  const hex = value.replace(/^(sha1|sha256)\s*:/i, '').replace(/[^0-9a-fA-F]/g, '');
  return hex.toLowerCase();
}

// chooseClientCertificate 决定要发送哪张客户端证书。
// 默认策略：没有“用户为该主机明确记住的指纹”时绝不自动选择（返回 index=-1）。
// rememberedFingerprint 为空 => 取消；给了就必须在候选列表里精确命中，否则也取消。
function chooseClientCertificate({ certificateList = [], rememberedFingerprint = '' } = {}) {
  if (!Array.isArray(certificateList) || certificateList.length === 0) {
    return { index: -1, reason: 'no-certificate' };
  }
  const wanted = normalizeCertFingerprint(rememberedFingerprint);
  if (!wanted) return { index: -1, reason: 'no-remembered-choice' };
  for (let i = 0; i < certificateList.length; i++) {
    const cert = certificateList[i];
    if (normalizeCertFingerprint(cert && cert.fingerprint) === wanted) {
      return { index: i, reason: 'remembered' };
    }
  }
  return { index: -1, reason: 'remembered-cert-absent' };
}

// sanitizeAuthSubmit 校验/净化用户从渲染层提交回来的账号口令。
// 账号必填；口令允许空串（部分内网 Basic 确实空密码），但必须是字符串。
// 返回 { ok, username, password }；超长或类型错误一律拒绝，不做截断后放行，
// 因为“悄悄截断口令”会让用户把错误的凭据发给服务器。
function sanitizeAuthSubmit(raw) {
  if (!raw || typeof raw !== 'object') return { ok: false, reason: 'bad-payload' };
  if (typeof raw.username !== 'string' || typeof raw.password !== 'string') {
    return { ok: false, reason: 'bad-type' };
  }
  const username = raw.username.replace(/[\x00-\x1f\x7f]/g, '').trim();
  const password = raw.password.replace(/[\x00]/g, '');
  if (username.length === 0 || username.length > MAX_USERNAME_CHARS) {
    return { ok: false, reason: 'bad-username' };
  }
  if (password.length > MAX_PASSWORD_CHARS) {
    return { ok: false, reason: 'password-too-long' };
  }
  return { ok: true, username, password };
}

// describeAuthScheme 给弹框一个人类可读的方案名（日志/UI 用），未知返回空串。
function describeAuthScheme(scheme) {
  switch (lowerTrim(scheme)) {
    case 'basic': return 'HTTP Basic 基本认证';
    case 'digest': return 'HTTP Digest 摘要认证';
    case 'ntlm': return 'NTLM / Windows 身份认证';
    case 'negotiate': return 'Negotiate / SPNEGO（Kerberos）';
    default: return '';
  }
}

// 最多为多少台主机记住客户端证书选择；超出淘汰最久未用的。客户端证书是强身份，
// 台账故意比普通站点设置小得多，避免长期累积出一份“访问过哪些需证书内网”的画像。
const MAX_REMEMBERED_CERT_HOSTS = 100;
const MAX_ISSUER_CHARS = 200;
const MAX_SUBJECT_CHARS = 200;
const MAX_SERIAL_CHARS = 128;

// certHostKey 与 authHostKey 一致（scheme://host:port），但客户端证书场景只应出现在
// https。这里仍复用 authHostKey，确保“记住证书”和“认证限流”看到的是同一台主体。
function certHostKey(rawUrl) {
  return authHostKey(rawUrl);
}

// summarizeClientCert 抽取证书里用于展示/记录的最小非敏感字段。不取公钥本体，
// 只留指纹与签发者/主题的短摘要。
function summarizeClientCert(certificate) {
  const c = certificate && typeof certificate === 'object' ? certificate : {};
  const fingerprint = normalizeCertFingerprint(c.fingerprint);
  return {
    fingerprint,
    issuer: clampText(c.issuerName || (c.issuer && c.issuer.name) || '', MAX_ISSUER_CHARS),
    subject: clampText(c.subjectName || (c.subject && c.subject.name) || '', MAX_SUBJECT_CHARS),
    serialNumber: clampText(c.serialNumber || c.serial || '', MAX_SERIAL_CHARS),
  };
}

// sanitizeCertChoiceRecord 把从磁盘读出的一条记录净化为可信结构；不合法返回 null。
function sanitizeCertChoiceRecord(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const host = clampText(raw.host, MAX_HOST_CHARS);
  const fingerprint = normalizeCertFingerprint(raw.fingerprint);
  if (!host || !fingerprint) return null;
  const updatedAt = Number(raw.updatedAt);
  return {
    host,
    fingerprint,
    issuer: clampText(raw.issuer, MAX_ISSUER_CHARS),
    subject: clampText(raw.subject, MAX_SUBJECT_CHARS),
    serialNumber: clampText(raw.serialNumber, MAX_SERIAL_CHARS),
    updatedAt: Number.isFinite(updatedAt) ? updatedAt : 0,
  };
}

// RememberedClientCertStore 是“主机 -> 记住的客户端证书指纹”的有界台账。
// 纯内存 + toJSON/loadJSON，落盘由 main.js 负责，便于单测不碰文件系统。
class RememberedClientCertStore {
  constructor({ max = MAX_REMEMBERED_CERT_HOSTS } = {}) {
    this.max = max;
    this.map = new Map();
  }

  // 已存在则更新并刷新 updatedAt；新增超容时淘汰 updatedAt 最小的一条。
  remember(host, certificate, now = Date.now()) {
    const key = certHostKey(`https://${host}/`);
    const hostKey = key || clampText(host, MAX_HOST_CHARS);
    if (!hostKey) return false;
    const summary = summarizeClientCert(certificate);
    if (!summary.fingerprint) return false;
    const record = { host: hostKey, ...summary, updatedAt: now };
    if (this.map.has(hostKey)) {
      this.map.set(hostKey, record);
      return true;
    }
    if (this.map.size >= this.max) {
      let oldestKey = null;
      let oldestTime = Infinity;
      for (const [k, v] of this.map) {
        if (v.updatedAt < oldestTime) {
          oldestTime = v.updatedAt;
          oldestKey = k;
        }
      }
      if (oldestKey) this.map.delete(oldestKey);
    }
    this.map.set(hostKey, record);
    return true;
  }

  get(host) {
    return this.map.get(certHostKey(`https://${host}/`)) || this.map.get(clampText(host, MAX_HOST_CHARS)) || null;
  }

  forget(host) {
    const key = certHostKey(`https://${host}/`);
    return this.map.delete(key) || this.map.delete(clampText(host, MAX_HOST_CHARS));
  }

  clear() {
    this.map.clear();
  }

  list() {
    return Array.from(this.map.values()).sort((a, b) => b.updatedAt - a.updatedAt);
  }

  toJSON() {
    return { version: 1, choices: this.list() };
  }

  loadJSON(raw) {
    let data;
    try {
      data = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      return 0;
    }
    const entries = data && Array.isArray(data.choices) ? data.choices : null;
    if (!entries) return 0;
    let loaded = 0;
    for (const e of entries) {
      const rec = sanitizeCertChoiceRecord(e);
      if (!rec) continue;
      this.map.set(rec.host, rec);
      loaded++;
      if (this.map.size >= this.max) break;
    }
    return loaded;
  }
}

// AuthPromptStats 聚合网络认证拦截/弹框计数，供安全页面板展示，不落敏感内容。
// 维度只到“原因码 + 方案”，绝不记录账号、口令、realm 原文。

module.exports = {
  normalizeCertFingerprint,
  chooseClientCertificate,
  sanitizeAuthSubmit,
  describeAuthScheme,
  MAX_REMEMBERED_CERT_HOSTS,
  MAX_ISSUER_CHARS,
  MAX_SUBJECT_CHARS,
  MAX_SERIAL_CHARS,
  certHostKey,
  summarizeClientCert,
  sanitizeCertChoiceRecord,
  RememberedClientCertStore,
};
