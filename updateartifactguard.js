'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-manifest',
  VERSION: 'invalid-version',
  URL: 'invalid-url',
  USERINFO: 'url-userinfo',
  HASH: 'invalid-hash',
  SIGNATURE: 'invalid-signature',
  SIZE: 'invalid-size',
  PLATFORM: 'unsupported-platform',
};

const MAX_SIZE = 2 * 1024 * 1024 * 1024;
const PLATFORMS = new Set(['win32-x64', 'win32-arm64', 'darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64']);
const SEMVER = /^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})(?:-[0-9A-Za-z.-]{1,40})?$/;
const SHA512_HEX = /^[a-f0-9]{128}$/;

function inspectUpdateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') return { ok: false, reason: REASON.INVALID, manifest: null };
  const version = typeof manifest.version === 'string' ? manifest.version.trim() : '';
  if (!SEMVER.test(version)) return { ok: false, reason: REASON.VERSION, manifest: null };
  let parsed;
  try {
    parsed = new URL(String(manifest.url || ''));
  } catch (err) {
    return { ok: false, reason: REASON.URL, manifest: null };
  }
  if (parsed.protocol !== 'https:') return { ok: false, reason: REASON.URL, manifest: null };
  if (parsed.username || parsed.password) return { ok: false, reason: REASON.USERINFO, manifest: null };
  const sha512 = typeof manifest.sha512 === 'string' ? manifest.sha512.trim().toLowerCase() : '';
  if (!SHA512_HEX.test(sha512)) return { ok: false, reason: REASON.HASH, manifest: null };
  const size = manifest.size;
  if (!Number.isInteger(size) || size <= 0 || size > MAX_SIZE) return { ok: false, reason: REASON.SIZE, manifest: null };
  const signature = typeof manifest.signature === 'string' ? manifest.signature.trim() : '';
  if (!/^[A-Za-z0-9+/]{86}==$/.test(signature)) return { ok: false, reason: REASON.SIGNATURE, manifest: null };
  const decoded = Buffer.from(signature, 'base64');
  if (decoded.length !== 64) return { ok: false, reason: REASON.SIGNATURE, manifest: null };
  const platform = typeof manifest.platform === 'string' ? manifest.platform.trim() : '';
  if (!PLATFORMS.has(platform)) return { ok: false, reason: REASON.PLATFORM, manifest: null };
  return {
    ok: true,
    reason: REASON.OK,
    manifest: { version, url: parsed.toString(), sha512, size, signature, platform },
  };
}

function applyUpdateArtifactGuard(manifest) {
  const result = inspectUpdateManifest(manifest);
  return { changed: !result.ok, reason: result.reason, manifest: result.manifest };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.INVALID:
      return '更新清单为空或不是对象';
    case REASON.VERSION:
      return '更新版本号不符合语义化版本';
    case REASON.URL:
      return '更新包地址不是 HTTPS';
    case REASON.USERINFO:
      return '更新包地址内嵌账号密码';
    case REASON.HASH:
      return '更新包 SHA-512 值非法';
    case REASON.SIGNATURE:
      return '更新包签名格式非法';
    case REASON.SIZE:
      return '更新包体积超出允许范围';
    case REASON.PLATFORM:
      return '更新包目标平台不受支持';
    default:
      return '更新清单校验通过';
  }
}

module.exports = {
  REASON,
  MAX_SIZE,
  PLATFORMS,
  inspectUpdateManifest,
  applyUpdateArtifactGuard,
  describeReason,
};
