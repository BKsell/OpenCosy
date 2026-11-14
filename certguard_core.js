'use strict';

// certguard.js —— TLS 证书错误判定与“例外放行”纯逻辑内核（不依赖 Electron）。
//
// 现代浏览器在证书校验失败时默认是“硬拦截”：宁可让页面打不开，也不把用户
// 暴露给中间人。Electron 默认行为相反——只要不显式 preventDefault，证书错误
// 会被静默放行，这对浏览器类应用是致命缺陷。main.js 里的 certificate-error
// 处理只负责接线，所有“什么错误能放行、按什么粒度放行、台账是否有效”的判断
// 都集中在这里，方便用 node:test 单测。
//
// 放行粒度不是“信任这个域名”，而是“信任这个域名 + 这张具体证书的指纹”。
// 这样即便用户为内网自签名站点加过例外，之后该域名被另一张（攻击者的）证书
// 劫持时仍然会重新拦截，而不是被一条宽泛白名单放过。

const {
  MAX_REASON_LENGTH,
  SOFT_ERROR_INFO,
  normalizeFingerprint,
  normalizeHost,
  parseCommonName,
  resolveFingerprint,
  summarizeCertificate
} = require('./certguard_resolve_core');

// 不可放行的“硬错误”：吊销 / 公钥固定 / CT 强制失败意味着这张证书即便用户
// 现在愿意冒险也不应被覆盖（Chrome 对这些同样不提供继续入口）。
const HARD_DENY_CODES = new Set([
  'ERR_CERT_REVOKED',
  'ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN',
  'ERR_CERT_KNOWN_INTERCEPTION_BLOCKED',
  'ERR_CERTIFICATE_TRANSPARENCY_REQUIRED',
]);

function shortFingerprint(fingerprint) {
  const fp = normalizeFingerprint(fingerprint);
  if (!fp) return '';
  return `${fp.slice(0, 8)}…${fp.slice(-8)}`;
}

// errorInfo 返回错误码是否可由用户显式放行，以及对应的标题/说明。
function errorInfo(code) {
  const key = String(code || '').trim().toUpperCase();
  if (HARD_DENY_CODES.has(key)) {
    return { code: key, overridable: false, title: '该证书问题不可绕过', detail: '证书被吊销、命中公钥固定或证书透明性策略，继续访问没有安全的“例外”可选。' };
  }
  const info = SOFT_ERROR_INFO[key];
  if (info) {
    return { code: key, overridable: true, title: info.title, detail: info.detail };
  }
  // 未知错误默认按硬错误处理（fail-closed），不提供继续入口。
  return { code: key || 'UNKNOWN', overridable: false, title: '证书校验失败', detail: '浏览器无法确认该站点证书的可信度，已默认阻止访问。' };
}

// classifyCertError 汇总一次证书失败事件的判定结果。
function classifyCertError({ url, error, certificate } = {}) {
  const host = normalizeHost(url);
  const info = errorInfo(error);
  const cert = summarizeCertificate(certificate);
  return {
    host,
    code: info.code,
    overridable: info.overridable,
    title: info.title,
    detail: info.detail,
    cert,
  };
}

// createException 生成一条“主机 + 指纹”绑定的例外记录。
function createException({ host, certificate, code, now = Date.now() }) {
  const h = normalizeHost(host);
  const fingerprint = resolveFingerprint(certificate);
  if (!h || !fingerprint) return null;
  return {
    host: h,
    fingerprint,
    subject: parseCommonName(certificate && certificate.subjectName).slice(0, 120),
    issuer: parseCommonName(certificate && certificate.issuerName).slice(0, 120),
    code: String(code || '').slice(0, MAX_REASON_LENGTH),
    addedAt: now,
  };
}

// exceptionMatches 判断当前失败的主机/指纹是否命中一条已批准的例外。
function exceptionMatches(entry, { host, fingerprint }) {
  if (!entry || typeof entry !== 'object') return false;
  return normalizeHost(entry.host) === normalizeHost(host) &&
    normalizeFingerprint(entry.fingerprint) === normalizeFingerprint(fingerprint);
}

// sanitizeExceptionRecord 读盘时消毒：只保留形状合法的记录，防止被手改的
// 台账文件注入大对象 / 伪造任意主机白名单。
function sanitizeExceptionRecord(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const host = normalizeHost(raw.host);
  const fingerprint = normalizeFingerprint(raw.fingerprint);
  if (!host || !fingerprint) return null;
  return {
    host,
    fingerprint,
    subject: String(raw.subject || '').slice(0, 120),
    issuer: String(raw.issuer || '').slice(0, 120),
    code: String(raw.code || '').slice(0, MAX_REASON_LENGTH),
    addedAt: Number(raw.addedAt) || 0,
  };
}

module.exports = { HARD_DENY_CODES, classifyCertError, createException, errorInfo, exceptionMatches, sanitizeExceptionRecord, shortFingerprint, ...require('./certguard_resolve_core') };
