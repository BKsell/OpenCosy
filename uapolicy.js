'use strict';

// uapolicy.js —— User-Agent 覆盖策略内核（防指纹 / 自定义标识）。
//
// 威胁模型：默认 UA 把 Electron + Chrome 精确版本 + 平台 + "OpenCosyBrowser/1.0.0"
// 一并外发，任何站点都能凭此唯一识别本浏览器与真实客户端；对注重隐私的用户，
// 这等于把"指纹锚点"直接送到每个请求里。旧版 Electron 默认 UA 甚至还会暴露
// Electron/xx.x.x 字符串，被指纹服务按特征直接命中。
//
// 本模块提供三种策略：
//   default       —— 沿用浏览器自算 UA（含 OpenCosy 标识，不额外改写）；
//   custom        —— 用户手写 UA 字符串（校验格式/长度/控制字符）；
//   chrome-random —— 从内置的常见桌面 Chrome UA 池里随机选一个（每会话首次
//                    请求时采样），抹掉 OpenCosy 标识与真实平台细节。
//
// 只做纯判定与字符串处理，供 node:test 直接验证；真正的 webRequest 改写与
// 持久化在 main.js 完成。

const { randomInt } = require('crypto');

const UA_MAX_LEN = 512;
const CUSTOM_MAX_LEN = 384;

// COMMON_CHROME_UAS 是常见桌面 Chrome 的 UA 池。只选稳定大版本与真实存在的
// 组合，避免编造不存在的平台串被指纹库识破。格式统一为
// Mozilla/5.0 (...) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<v> Safari/537.36。
const COMMON_CHROME_UAS = Object.freeze([
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
]);

const MODES = Object.freeze({
  DEFAULT: 'default',
  CUSTOM: 'custom',
  CHROME_RANDOM: 'chrome-random',
});

// DEFAULT_POLICY 是未配置时的基线策略。
const DEFAULT_POLICY = Object.freeze({ mode: MODES.DEFAULT, custom: '' });

// hasControlChar 检测字符串里的控制字符（含 NUL 与各种不可见编排符）。
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

// validateCustomUa 校验用户自定义 UA：必须非空、长度受限、无控制字符。
// 不强制以 Mozilla/ 开头——有的内网应用要求固定简写 UA，但拒绝空串与脏字符。
// 返回 {ok, reason}。
function validateCustomUa(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { ok: false, reason: 'UA 不能为空' };
  }
  const trimmed = raw.trim();
  if (trimmed.length > CUSTOM_MAX_LEN) {
    return { ok: false, reason: `自定义 UA 超过 ${CUSTOM_MAX_LEN} 字符上限` };
  }
  if (hasControlChar(trimmed)) {
    return { ok: false, reason: '自定义 UA 含控制字符' };
  }
  return { ok: true, reason: '' };
}

// sanitizePolicy 把任意来源（持久化文件 / renderer 输入）收敛成合法策略对象。
// 未知模式回落 default；custom 模式下的非法字符串回落 default，避免脏数据
// 直接喂给 webRequest。
function sanitizePolicy(raw) {
  if (!raw || typeof raw !== 'object') return { ...DEFAULT_POLICY };
  const mode = MODES[String(raw.mode).toUpperCase().replace('-', '_')] || MODES.DEFAULT;
  if (mode === MODES.CUSTOM) {
    const v = validateCustomUa(raw.custom);
    if (!v.ok) return { mode: MODES.DEFAULT, custom: '' };
    return { mode, custom: raw.custom.trim() };
  }
  return { mode, custom: '' };
}

// pickRandomChromeUa 从池中随机取一条。注入 rand 便于测试固定种子。
function pickRandomChromeUa(rand) {
  const fn = typeof rand === 'function' ? rand : randomInt;
  return COMMON_CHROME_UAS[fn(COMMON_CHROME_UAS.length)];
}

// resolveUa 依据策略返回实际应外发的 UA。defaultUa 为浏览器自算 UA。
// chrome-random 模式从池中取样；custom 模式返回用户串；其余返回 defaultUa。
function resolveUa(policy, defaultUa, rand) {
  const p = sanitizePolicy(policy);
  if (p.mode === MODES.CUSTOM) return p.custom;
  if (p.mode === MODES.CHROME_RANDOM) return pickRandomChromeUa(rand);
  return defaultUa;
}

// policyToPlain 输出可供 UI / IPC 展示的视图（不含内部状态）。
function policyToPlain(policy) {
  const p = sanitizePolicy(policy);
  return {
    mode: p.mode,
    custom: p.custom,
    poolSize: COMMON_CHROME_UAS.length,
  };
}

// countUaOverrides 是改写次数的纯递增器（防 overflow：超过 2^53 封顶）。
function countUaOverrides(n) {
  return typeof n === 'number' && n < Number.MAX_SAFE_INTEGER ? n + 1 : 1;
}

module.exports = {
  UA_MAX_LEN,
  CUSTOM_MAX_LEN,
  COMMON_CHROME_UAS,
  MODES,
  DEFAULT_POLICY,
  hasControlChar,
  validateCustomUa,
  sanitizePolicy,
  pickRandomChromeUa,
  resolveUa,
  policyToPlain,
  countUaOverrides,
};
