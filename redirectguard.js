'use strict';

// redirectguard.js —— 服务端重定向链（will-redirect / will-frame-redirect）专用守卫。
//
// 为什么单独存在：
//   navguard 负责“页面主动导航”的来源矩阵（远程网页能不能顶到 file:/cosy:），
//   但 HTTP 3xx 服务端重定向有几类它不专门处理的威胁：
//     1) 降级：https 登录流程中途被 302 到 http:// 同名主机，凭据/Cookie 在明文链路泄露；
//     2) 环路：恶意/故障服务器反复 302（A→B→A…），标签卡死、不断发请求放大负载；
//     3) 凭据式钓鱼：跳到 http://user:pass@host 这种带 userinfo 的地址；
//     4) 重定向到危险 scheme：http(s) 页面 302 到 file:/javascript:/data:/cosy:。
//   本内核是“有状态纯判定”：每条 webContents 维护一条链状态，did-navigate 成功后重置。

const REDIRECT_MAX_CHAIN = 20;          // 单条导航允许的最大连续重定向次数
const REDIRECT_MAX_REPEAT_URL = 3;     // 同一目标 URL 最多出现次数（超过判环路）
const REDIRECT_BLOCK = 'block';
const REDIRECT_ALLOW = 'allow';

const DANGEROUS_TARGET_SCHEMES = new Set([
  'file:', 'javascript:', 'data:', 'vbscript:', 'about:', 'cosy:', 'blob:',
]);

function safeParseUrl(raw) {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

// registrable-ish 主机标签：取 host 最后两段做“站点”近似比较（足以判断跨站跳转，
// 不依赖外部公共后缀表，避免引入数据文件）。IP/localhost 原样返回 host。
function siteLabel(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return '';
  if (/^\[?[\d:a-f]+\]?$/i.test(h) || /^\d+\.\d+\.\d+\.\d+$/.test(h) || h === 'localhost') {
    return h;
  }
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  return parts.slice(-2).join('.');
}

function createRedirectState(now) {
  return {
    startedAt: now || Date.now(),
    count: 0,
    seenUrls: new Map(),   // 规范化目标 URL -> 出现次数
    hosts: [],
    startHost: '',
    startHttps: false,
  };
}

function normalizeForCompare(u) {
  // 仅用于环路判定：去掉末尾斜杠与 fragment，query 保留（不同 query 视为不同目标）。
  let s = String(u || '');
  try {
    const parsed = new URL(u);
    parsed.hash = '';
    s = parsed.href;
  } catch {}
  return s.replace(/\/+$/, '');
}

// resetState 在一次成功的顶层导航后调用，开始下一条链。
function resetState(state, now) {
  const fresh = createRedirectState(now);
  for (const k of Object.keys(state)) delete state[k];
  Object.assign(state, fresh);
}

// decideRedirect 判定一次重定向。state 由调用方按 webContents 长期持有。
// input: { fromUrl, toUrl, isMainFrame }
// 返回 { action, reasons:[], state }。
function decideRedirect(state, input, now) {
  const st = state || createRedirectState(now);
  const reasons = [];
  const from = safeParseUrl(input && input.fromUrl);
  const to = safeParseUrl(input && input.toUrl);

  if (!to) {
    reasons.push('redirect-malformed-target');
    return { action: REDIRECT_BLOCK, reasons, state: st };
  }

  const toScheme = to.protocol.toLowerCase();
  if (DANGEROUS_TARGET_SCHEMES.has(toScheme)) {
    reasons.push('redirect-dangerous-scheme');
  }

  // 目标带 userinfo（http://u:p@host）——典型凭据钓鱼/歧义地址。
  if (to.username || to.password) {
    reasons.push('redirect-userinfo');
  }

  if (from) {
    const fromScheme = from.protocol.toLowerCase();
    // 显式降级：https → http。
    if (fromScheme === 'https:' && toScheme === 'http:') {
      reasons.push('redirect-downgrade');
    }
    // 链起点是 https，则后续任一非 https 目标都视为安全级别下降（只针对 http(s) 主体）。
    if (st.startHttps && toScheme === 'http:') {
      if (!reasons.includes('redirect-downgrade')) reasons.push('redirect-chain-downgrade');
    }
  }

  // 链长度与环路。
  st.count += 1;
  const key = normalizeForCompare(input.toUrl);
  const times = (st.seenUrls.get(key) || 0) + 1;
  st.seenUrls.set(key, times);
  if (times > REDIRECT_MAX_REPEAT_URL) {
    reasons.push('redirect-loop');
  }
  if (st.count > REDIRECT_MAX_CHAIN) {
    reasons.push('redirect-chain-too-long');
  }

  // 记录主机轨迹（供上层展示/统计），限制体积。
  if (st.hosts.length < REDIRECT_MAX_CHAIN + 4) {
    st.hosts.push(siteLabel(to.hostname));
  }

  if (!st.startHost && from) {
    st.startHost = siteLabel(from.hostname);
    st.startHttps = from.protocol.toLowerCase() === 'https:';
  }

  const action = reasons.length ? REDIRECT_BLOCK : REDIRECT_ALLOW;
  return { action, reasons, state: st };
}

// describeReason 把内部 code 转成中文说明，供安全面板/日志使用。
function describeReason(code) {
  switch (code) {
    case 'redirect-dangerous-scheme': return '重定向到危险协议（file/data/javascript 等）';
    case 'redirect-userinfo': return '重定向目标在地址中内嵌账号密码';
    case 'redirect-downgrade': return 'HTTPS 被重定向降级到 HTTP';
    case 'redirect-chain-downgrade': return '安全链路中途降级到明文 HTTP';
    case 'redirect-loop': return '检测到重定向环路';
    case 'redirect-chain-too-long': return '重定向链过长';
    case 'redirect-malformed-target': return '重定向目标地址无法解析';
    default: return code;
  }
}

module.exports = {
  REDIRECT_MAX_CHAIN,
  REDIRECT_MAX_REPEAT_URL,
  REDIRECT_BLOCK,
  REDIRECT_ALLOW,
  DANGEROUS_TARGET_SCHEMES,
  siteLabel,
  createRedirectState,
  resetState,
  normalizeForCompare,
  decideRedirect,
  describeReason,
};
