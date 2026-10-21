'use strict';

// postmessageguard.js —— window.postMessage 跨文档通信的安全裁决内核。
//
// 威胁模型：
//   页面 / 内部特权页常用 window.addEventListener('message', …) 与 iframe、
//   弹窗、父窗口通信。这里的漏洞不是 Electron IPC（那由 ipcguard 管），而是
//   Web 标准的 window.postMessage 通道，常见错误：
//     1. 收到消息不校验 event.origin：任意标签页 / 被嵌入的恶意 iframe 都能
//        下发“关闭标签/读取令牌/执行动作”等伪造指令；
//     2. 用 endsWith / includes 匹配白名单：evilpaypal.com、paypal.com.evil.net
//        这类主机轻易绕过；
//     3. 外发时 targetOrigin:'*' 却带敏感数据，消息会被任何抢先注册的窗口收走；
//     4. 信任字符串 origin "null"（sandbox iframe / data: / file: 的来源就是
//        字符串 null，无法区分彼此）；
//     5. data 里允许 __proto__/constructor 键，或嵌套过深/超大，下游
//        合并时触发原型污染或 UI 卡顿。
//
// 本模块纯函数、不触 DOM：调用方在 message 处理器入口把归一化后的
// {origin,data,channel} 传入，依据策略裁决；外发前用 auditOutgoing 检查。

const DEFAULT_POLICY = Object.freeze({
  requireHttps: true,
  allowNullOrigin: false,
  allowLocalhostHttp: false,
  allowedOrigins: [],       // 完整 origin 精确匹配，如 'https://app.example.com'
  allowedHostSuffixes: [],  // 仅主机后缀（'.example.com'），点边界受控
  allowedPorts: [],         // 显式端口白名单（443/无端口永远允许 https）
  allowedChannels: [],      // 允许的消息类型/频道名；为空表示不启用频道白名单
  maxDepth: 8,
  maxKeys: 200,
  maxPayloadBytes: 32768,
});

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

// 解析标准 origin：scheme://host(:port)。不使用正则，纯字符切分。
// 返回 { scheme, host, port } 或 null（非法）。
function parseOrigin(origin) {
  if (typeof origin !== 'string' || origin === '') return null;
  const idx = origin.indexOf('://');
  if (idx <= 0) return null;
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return null;
  let rest = origin.slice(idx + 3);
  // origin 只含主机（可带端口），不含路径/查询/锚点。
  if (rest === '' || rest.includes('/') || rest.includes('?') || rest.includes('#')) {
    return null;
  }
  let host = rest;
  let port = 0;
  // IPv6 字面量 [::1] 先整体处理。
  if (host[0] === '[') {
    const close = host.indexOf(']');
    if (close < 0) return null;
    host = host.slice(0, close + 1);
    const tail = rest.slice(close + 1);
    if (tail.startsWith(':')) port = parsePort(tail.slice(1));
    else if (tail !== '') return null;
  } else {
    const colon = rest.indexOf(':');
    if (colon >= 0) {
      host = rest.slice(0, colon);
      port = parsePort(rest.slice(colon + 1));
      if (port < 0) return null;
    }
  }
  if (host === '') return null;
  return { scheme, host: host.toLowerCase(), port };
}

function parsePort(s) {
  if (s === '') return 0;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return -1;
    n = n * 10 + (c - 48);
    if (n > 65535) return -1;
  }
  return n;
}

function isLocalHost(host) {
  return LOCAL_HOSTS.has(host) || host === '[::1]';
}

// host 受控后缀匹配：host 等于 base（base 不带前导点时）或以 '.'+base 结尾。
function hostMatchesSuffix(host, suffix) {
  let base = suffix.toLowerCase();
  if (base.startsWith('.')) base = base.slice(1);
  if (base === '') return false;
  return host === base || host.endsWith('.' + base);
}

// originAllowed 判定来源 origin 是否在策略内。
function originAllowed(origin, policy) {
  if (origin === 'null') {
    return policy.allowNullOrigin ? { ok: true } : { ok: false, reason: 'null-origin' };
  }
  const parsed = parseOrigin(origin);
  if (!parsed) return { ok: false, reason: 'bad-origin' };

  if (parsed.scheme === 'http') {
    // 本机开发 http：主机必须是本地回环；allowLocalhostHttp 是显式开关，
    // 满足即放行（不再叠加跨域白名单），其余明文 http 一律拒绝。
    if (policy.allowLocalhostHttp && isLocalHost(parsed.host)) {
      return { ok: true };
    }
    return { ok: false, reason: 'insecure-scheme' };
  }

  if (parsed.port !== 0 && parsed.port !== 443) {
    if (!policy.allowedPorts.includes(parsed.port)) {
      return { ok: false, reason: 'port-not-allowed' };
    }
  }
  return matchBySchemeHost(parsed, policy);
}

// matchBySchemeHost 在精确 origin 与受控后缀白名单内按 scheme+host 匹配；
// 端口是否合规由调用方先行用 allowedPorts 把关。
function matchBySchemeHost(parsed, policy) {
  for (const o of policy.allowedOrigins) {
    const op = parseOrigin(o);
    if (op && op.scheme === parsed.scheme && op.host === parsed.host) {
      return { ok: true };
    }
  }
  for (const suf of policy.allowedHostSuffixes) {
    if (hostMatchesSuffix(parsed.host, suf)) {
      return { ok: true };
    }
  }
  return { ok: false, reason: 'origin-not-whitelisted' };
}

// —— data 结构安全 ——

function isPrototypeKey(key) {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
}

// 遍历 data，校验深度、键数量、危险原型键、字节规模。返回违规原因或 ''。
function inspectMessageData(data, policy) {
  let keys = 0;
  let bytes = 0;
  const stack = [{ v: data, d: 0 }];
  while (stack.length > 0) {
    const { v, d } = stack.pop();
    if (d > policy.maxDepth) return 'data-too-deep';
    const t = typeof v;
    if (v === null || t === 'undefined') continue;
    if (t === 'string') {
      bytes += v.length;
      if (bytes > policy.maxPayloadBytes) return 'data-too-large';
      continue;
    }
    if (t === 'number' || t === 'boolean') {
      bytes += 8;
      continue;
    }
    if (t === 'function' || t === 'symbol' || t === 'bigint') {
      return 'data-illegal-type';
    }
    if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push({ v: v[i], d: d + 1 });
      continue;
    }
    if (t === 'object') {
      // 拒绝明显的宿主对象（含 DOM 节点特征 / window 自引用特征）。
      if (typeof v.nodeType === 'number' || v.window === v) {
        return 'data-host-object';
      }
      for (const k of Object.keys(v)) {
        if (isPrototypeKey(k)) return 'prototype-key';
        keys++;
        if (keys > policy.maxKeys) return 'data-too-many-keys';
        stack.push({ v: v[k], d: d + 1 });
      }
    }
  }
  return '';
}

function channelOf(data) {
  if (data && typeof data === 'object' && typeof data.channel === 'string') {
    return data.channel;
  }
  if (data && typeof data === 'object' && typeof data.type === 'string') {
    return data.type;
  }
  return '';
}

// decideIncoming 裁决一条收到的 message。
// msg: { origin, data }；channel 从 data.channel / data.type 取。
function decideIncoming(msg, override) {
  const policy = Object.assign({}, DEFAULT_POLICY, override || {});
  if (!msg || typeof msg !== 'object') {
    return { allow: false, reason: 'bad-message' };
  }
  const originCheck = originAllowed(String(msg.origin == null ? '' : msg.origin), policy);
  if (!originCheck.ok) {
    return { allow: false, reason: originCheck.reason };
  }
  if (msg.data === null || typeof msg.data !== 'object') {
    // 允许纯字符串握手类消息由调用方处理，但默认要求结构化 data。
    if (typeof msg.data === 'string') {
      if (msg.data.length > policy.maxPayloadBytes) {
        return { allow: false, reason: 'data-too-large' };
      }
      return { allow: true, reason: '', channel: '' };
    }
    return { allow: false, reason: 'data-not-object' };
  }
  const structural = inspectMessageData(msg.data, policy);
  if (structural) return { allow: false, reason: structural };

  const channel = channelOf(msg.data);
  if (policy.allowedChannels.length > 0) {
    if (!channel || !policy.allowedChannels.includes(channel)) {
      return { allow: false, reason: 'channel-not-whitelisted' };
    }
  }
  return { allow: true, reason: '', channel };
}

// auditOutgoing 外发检查：targetOrigin '*' 时不得携带敏感字段。
// sensitiveKeys 命中（任意层级的键名）即判危险。
function auditOutgoing(targetOrigin, payload, sensitiveKeys) {
  const to = typeof targetOrigin === 'string' ? targetOrigin : '';
  if (to === '') return { ok: false, reason: 'empty-target-origin' };
  if (to === '*' || to === 'null') {
    if (payload == null) return { ok: true, broadcast: true };
    const found = findSensitiveKey(payload, new Set((sensitiveKeys || []).map(s => s.toLowerCase())));
    if (found) return { ok: false, broadcast: true, reason: 'sensitive-on-wildcard', key: found };
    return { ok: true, broadcast: true };
  }
  // 即便指定了具体 origin，也要它是合法可解析的 http(s) origin。
  if (!parseOrigin(to)) return { ok: false, reason: 'bad-target-origin' };
  return { ok: true, broadcast: false };
}

function findSensitiveKey(v, set) {
  if (v === null || typeof v !== 'object') return '';
  const stack = [v];
  let guard = 0;
  while (stack.length > 0 && guard < 10000) {
    guard++;
    const cur = stack.pop();
    for (const k of Object.keys(cur)) {
      if (set.has(k.toLowerCase())) return k;
      if (cur[k] && typeof cur[k] === 'object') stack.push(cur[k]);
    }
  }
  return '';
}

// buildPolicy 便于调用方用只读白名单构造策略。
function buildPolicy(partial) {
  return Object.assign({}, DEFAULT_POLICY, partial || {});
}

module.exports = {
  DEFAULT_POLICY,
  parseOrigin,
  hostMatchesSuffix,
  originAllowed,
  inspectMessageData,
  decideIncoming,
  auditOutgoing,
  buildPolicy,
  isPrototypeKey,
};
