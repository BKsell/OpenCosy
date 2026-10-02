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

const crypto = require('node:crypto');

// 不可放行的“硬错误”：吊销 / 公钥固定 / CT 强制失败意味着这张证书即便用户
// 现在愿意冒险也不应被覆盖（Chrome 对这些同样不提供继续入口）。
const HARD_DENY_CODES = new Set([
  'ERR_CERT_REVOKED',
  'ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN',
  'ERR_CERT_KNOWN_INTERCEPTION_BLOCKED',
  'ERR_CERTIFICATE_TRANSPARENCY_REQUIRED',
]);

// 可由用户“明知风险后显式放行”的软错误，以及中文说明。
const SOFT_ERROR_INFO = {
  ERR_CERT_AUTHORITY_INVALID: {
    title: '证书颁发机构不受信任',
    detail: '该证书不是由系统信任的机构签发的，可能是自签名证书，也可能正遭遇中间人代理劫持。',
  },
  ERR_CERT_COMMON_NAME_INVALID: {
    title: '证书域名不匹配',
    detail: '证书登记的域名与当前站点地址不一致，可能是配置错误，也可能是被转发到了仿冒站点。',
  },
  ERR_CERT_DATE_INVALID: {
    title: '证书日期无效',
    detail: '证书已过期或尚未生效。请先确认本机系统时间正确；若时间无误仍报错，应停止访问。',
  },
  ERR_CERT_WEAK_SIGNATURE_ALGORITHM: {
    title: '证书签名算法过弱',
    detail: '该证书使用了已被淘汰的弱签名算法（如 SHA-1），无法证明证书未被伪造。',
  },
  ERR_CERT_WEAK_KEY: {
    title: '证书密钥过弱',
    detail: '证书公钥长度不足，可被现实算力破解，无法保证连接的机密性。',
  },
  ERR_CERT_NAME_CONSTRAINT_VIOLATED: {
    title: '证书名称约束冲突',
    detail: '签发该证书的上级 CA 限制了允许的域名范围，而当前域名不在范围内。',
  },
  ERR_CERT_VALIDITY_TOO_LONG: {
    title: '证书有效期过长',
    detail: '证书有效期超过了现行规范允许的上限，不符合现代证书策略。',
  },
  ERR_CERT_UNABLE_TO_CHECK_REVOCATION: {
    title: '无法核验证书吊销状态',
    detail: '浏览器无法确认该证书是否已被吊销，离线或被代理拦截时会出现此错误。',
  },
  ERR_CERT_NON_UNIQUE_NAME: {
    title: '证书主体名称不唯一',
    detail: '证书缺少唯一标识，可能无法可靠区分真实站点。',
  },
  ERR_CERT_CONTAINS_ERRORS: {
    title: '证书包含错误',
    detail: '证书内容存在校验错误，无法确认其可信度。',
  },
};

// 主机名长度（DNS 253）与指纹（SHA-256 hex 64）上限，写盘前统一裁剪。
const MAX_HOST_LENGTH = 253;
const FINGERPRINT_HEX_LENGTH = 64;
const MAX_REASON_LENGTH = 80;

// normalizeHost 把“URL 或裸主机名”归一化成例外台账用的主机键。
// 只取小写、去末尾点的 hostname；端口不参与（同一张证书对该主机的所有端口
// 语义一致，且 Electron 证书对象本身不含端口）。无法解析时返回 null。
function normalizeHost(input) {
  if (input == null) return null;
  let host = String(input).trim().toLowerCase();
  if (!host) return null;
  if (host.includes('/') || host.includes(':') || host.includes('%')) {
    try {
      const u = new URL(host.includes('://') ? host : `https://${host}`);
      host = u.hostname;
    } catch {
      return null;
    }
  }
  // IPv6 URL 的 hostname 会被方括号包成 [::1]，这里去掉方括号。
  host = host.replace(/^\[|\]$/g, '');
  host = host.replace(/\.$/, '');
  if (!host || host.length > MAX_HOST_LENGTH) return null;
  // 主机键只允许合法字符：字母数字、点、连字符、冒号（IPv6）。
  if (!/^[a-z0-9.:_-]+$/.test(host)) return null;
  return host;
}

// normalizeFingerprint 统一指纹为无冒号小写 hex。Electron 的
// certificate.fingerprint 形如 "sha256/AA:BB:..."；也可能直接给 DER。
function normalizeFingerprint(value) {
  if (value == null) return '';
  let fp = String(value).trim().toLowerCase();
  const slash = fp.indexOf('/');
  if (slash >= 0) fp = fp.slice(slash + 1);
  fp = fp.replace(/[^0-9a-f]/g, '');
  if (fp.length !== FINGERPRINT_HEX_LENGTH) return '';
  return fp;
}

// derFingerprint 从证书 DER（base64）计算 SHA-256 指纹，作为 fingerprint
// 字段缺失时的权威来源。
function derFingerprint(derBase64) {
  if (!derBase64 || typeof derBase64 !== 'string') return '';
  try {
    const der = Buffer.from(derBase64, 'base64');
    if (!der.length) return '';
    return crypto.createHash('sha256').update(der).digest('hex');
  } catch {
    return '';
  }
}

// resolveFingerprint 优先用 Electron 给的指纹，缺失或异常时回退 DER 计算。
function resolveFingerprint(certificate) {
  if (!certificate || typeof certificate !== 'object') return '';
  const direct = normalizeFingerprint(certificate.fingerprint);
  if (direct) return direct;
  return derFingerprint(certificate.data);
}

// parseDistinguishedName 从 "CN=x, O=y" 形式的 issuer/subject 里取 CN。
// Electron 给的是已拼好的字符串，这里做宽松解析，不引入 X.500 库。
function parseCommonName(dn) {
  if (!dn || typeof dn !== 'string') return '';
  for (const part of dn.split(',')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toUpperCase();
    const val = part.slice(eq + 1).trim();
    if (key === 'CN' || key === 'COMMONNAME') return val.slice(0, 120);
  }
  return '';
}

// summarizeCertificate 生成给拦截页 / 台账展示用的安全摘要，字段全部限长，
// 原始证书对象绝不直接进渲染进程。
function summarizeCertificate(certificate) {
  if (!certificate || typeof certificate !== 'object') return null;
  const fingerprint = resolveFingerprint(certificate);
  return {
    subject: parseCommonName(certificate.subjectName) || String(certificate.subjectName || '').slice(0, 120),
    issuer: parseCommonName(certificate.issuerName) || String(certificate.issuerName || '').slice(0, 120),
    fingerprint,
    validStart: Number(certificate.validStart) || 0,
    validExpiry: Number(certificate.validExpiry) || 0,
  };
}

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

module.exports = {
  HARD_DENY_CODES,
  SOFT_ERROR_INFO,
  MAX_HOST_LENGTH,
  normalizeHost,
  normalizeFingerprint,
  derFingerprint,
  resolveFingerprint,
  parseCommonName,
  summarizeCertificate,
  shortFingerprint,
  errorInfo,
  classifyCertError,
  createException,
  exceptionMatches,
  sanitizeExceptionRecord,
};
