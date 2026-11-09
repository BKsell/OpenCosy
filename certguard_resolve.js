'use strict';

const crypto = require('node:crypto');

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

module.exports = {
  FINGERPRINT_HEX_LENGTH,
  MAX_HOST_LENGTH,
  MAX_REASON_LENGTH,
  SOFT_ERROR_INFO,
  derFingerprint,
  normalizeFingerprint,
  normalizeHost,
  parseCommonName,
  resolveFingerprint,
  summarizeCertificate
};
