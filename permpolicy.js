'use strict';

// permpolicy.js —— Permissions-Policy 响应头的可测试构建 / 解析内核。
//
// 历史实现把一段指令字符串硬编码在主进程里：想新增特性、按设置放开某能力、
// 或验证站点已下发的策略时都无从下手。本模块把“哪些浏览器能力允许谁用”
// 收敛成数据 + 纯函数，主进程只负责把结果写进响应头。
//
// 安全底线：广告 / 跨站兴趣组 / 隐私令牌相关特性（interest-cohort、
// join-ad-interest-group、run-ad-auction、browsing-topics、private-state-token-*）
// 一律强制关闭，调用方无法通过选项放开——这些能力对正常网页无用，却是
// 跨站追踪与再识别的通道。

// FORCED_DISABLE：无论调用方给什么选项都强制 () 的特性。
const FORCED_DISABLE = Object.freeze([
  'interest-cohort',
  'join-ad-interest-group',
  'run-ad-auction',
  'browsing-topics',
  'private-state-token-issuance',
  'private-state-token-redemption',
]);

// 可由调用方配置 allowlist 的“能力类”特性白名单。
const CONFIGURABLE_FEATURES = Object.freeze([
  'camera',
  'microphone',
  'geolocation',
  'payment',
  'usb',
  'hid',
  'serial',
  'bluetooth',
  'midi',
  'magnetometer',
  'gyroscope',
  'accelerometer',
  'display-capture',
  'clipboard-read',
  'clipboard-write',
  'fullscreen',
  'idle-detection',
  'wake-lock',
  'autoplay',
]);

const ALL_FEATURES = new Set([...FORCED_DISABLE, ...CONFIGURABLE_FEATURES]);

const ALLOW_TOKEN_SELF = 'self';
const ALLOW_TOKEN_NONE = 'none';
const ALLOW_TOKEN_ANY = '*';

function isObj(v) {
  return v !== null && typeof v === 'object';
}

// isValidFeatureName 仅接受已知特性，杜绝把任意字符串塞进响应头（头注入）。
function isValidFeatureName(name) {
  return typeof name === 'string' && ALL_FEATURES.has(name);
}

// normalizeAllowValue 把一种允许配置归一为 allowlist 数组：
//   'none'/false/[] -> []（生成 key=()）
//   'self'/true     -> ['self']
//   '*'             -> ['*']
//   字符串源/源数组   -> 仅保留 https 源（或 self/*）
// 返回 null 表示配置非法，调用方应忽略该特性。
function normalizeAllowValue(value) {
  if (value === false || value === null || value === undefined) return [];
  if (value === true) return [ALLOW_TOKEN_SELF];
  if (typeof value === 'string') {
    const v = value.trim().toLowerCase();
    if (v === ALLOW_TOKEN_NONE || v === '') return [];
    if (v === ALLOW_TOKEN_SELF) return [ALLOW_TOKEN_SELF];
    if (v === ALLOW_TOKEN_ANY) return [ALLOW_TOKEN_ANY];
    return sanitizeOrigins([value]);
  }
  if (Array.isArray(value)) {
    return sanitizeOrigins(value);
  }
  return null;
}

// sanitizeOrigins 仅保留可信源：'self'/'*' 标记，或带主机的 https 源。
// 拒绝 javascript:/data:/file: 与带路径/查询的串，防止头注入。
function sanitizeOrigins(list) {
  const out = [];
  for (const item of list) {
    if (typeof item !== 'string') continue;
    const v = item.trim();
    if (!v) continue;
    if (v === ALLOW_TOKEN_SELF || v === ALLOW_TOKEN_ANY) {
      if (!out.includes(v)) out.push(v);
      continue;
    }
    let u;
    try {
      u = new URL(v);
    } catch {
      continue;
    }
    if (u.protocol !== 'https:') continue;
    if (!u.hostname) continue;
    // Permissions-Policy 的源不携带路径/查询/碎片，只保留 scheme://host[:port]。
    const origin = u.port ? `${u.protocol}//${u.hostname}:${u.port}` : `${u.protocol}//${u.hostname}`;
    if (!out.includes(origin)) out.push(origin);
  }
  return out;
}

// formatAllowlist 把归一后的数组渲染成括号内 allowlist。
function formatAllowlist(allow) {
  if (!Array.isArray(allow) || allow.length === 0) return '()';
  // self / * 不加引号；具体源按规范可加引号，Chromium 两种都接受，这里加引号更稳。
  const inner = allow.map((t) => {
    if (t === ALLOW_TOKEN_SELF) return 'self';
    if (t === ALLOW_TOKEN_ANY) return '*';
    return `"${t}"`;
  }).join(' ');
  return `(${inner})`;
}

// buildPermissionsPolicy 依据调用方给定的特性配置，合并强制关闭项，
// 返回完整的 Permissions-Policy 头值。
// options.featureOverrides: { camera: 'self', payment: ['*'], geolocation: [] }
function buildPermissionsPolicy(options) {
  const overrides = isObj(options) && isObj(options.featureOverrides) ? options.featureOverrides : {};
  const directives = new Map();

  for (const feature of CONFIGURABLE_FEATURES) {
    if (!Object.prototype.hasOwnProperty.call(overrides, feature)) continue;
    const allow = normalizeAllowValue(overrides[feature]);
    if (allow === null) continue;
    directives.set(feature, allow);
  }

  // 强制关闭项最后写入，保证任何调用方覆盖都无法放开。
  for (const feature of FORCED_DISABLE) {
    directives.set(feature, []);
  }

  // 稳定输出顺序：可配置项按声明顺序，再追加强制项，避免头值抖动导致缓存/测试不稳。
  const ordered = [...CONFIGURABLE_FEATURES.filter((f) => directives.has(f)), ...FORCED_DISABLE];
  return ordered.map((f) => `${f}=${formatAllowlist(directives.get(f))}`).join(', ');
}

// parsePermissionsPolicy 解析现有头值为 { feature: [] | ['self'|origin...] }。
// 仅用于读取 / 对比站点策略；非法片段被跳过。
function parsePermissionsPolicy(headerValue) {
  const result = {};
  if (typeof headerValue !== 'string' || !headerValue.trim()) return result;
  const parts = headerValue.split(',');
  for (const part of parts) {
    const seg = part.trim();
    const eq = seg.indexOf('=');
    if (eq === -1) continue;
    const feature = seg.slice(0, eq).trim().toLowerCase();
    if (!isValidFeatureName(feature)) continue;
    const rest = seg.slice(eq + 1).trim();
    const m = /^\((.*)\)$/.exec(rest);
    if (!m) continue;
    const tokens = m[1].trim() === ''
      ? []
      : m[1].trim().split(/\s+/).map((t) => {
        const q = /^"(.*)"$/.exec(t);
        return q ? q[1] : t;
      });
    result[feature] = tokens;
  }
  return result;
}

// isFeatureDisabled 便于主进程/UI 判断某特性在给定头值下是否为全禁。
function isFeatureDisabled(headerValue, feature) {
  if (!isValidFeatureName(feature)) return false;
  const parsed = parsePermissionsPolicy(headerValue);
  if (!Object.prototype.hasOwnProperty.call(parsed, feature)) return false;
  return parsed[feature].length === 0;
}

// defaultHeader 返回“只强制关闭广告/追踪特性”的默认头值（等价历史硬编码，
// 另补 browsing-topics 与 payment 之外能力不默认禁，以免误伤摄像头等网站）。
function defaultHeader() {
  return buildPermissionsPolicy({ featureOverrides: {} });
}

module.exports = {
  FORCED_DISABLE,
  CONFIGURABLE_FEATURES,
  ALL_FEATURES,
  isValidFeatureName,
  normalizeAllowValue,
  sanitizeOrigins,
  formatAllowlist,
  buildPermissionsPolicy,
  parsePermissionsPolicy,
  isFeatureDisabled,
  defaultHeader,
};
