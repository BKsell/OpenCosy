'use strict';

// urlresolve.js —— 从"可能非法的字符串"里安全取 URL 字段的唯一内核。
//
// 权限弹窗、设备授权、Referer 收敛、缩放记忆、CSP 归属等十几处都需要
// "new URL(x).origin"。历史写法各抄一遍 try/catch，且 fallback 不一致
// （有的返回 null、有的返回 ''），一旦哪处漏了 try，一个畸形 URL 就会抛到
// 事件回调里把整条安全加固链打断。这里统一收口：
//
//   - 输入不是字符串 / 为空 / URL 解析失败时，一律返回调用方给定的 fallback；
//   - 解析成功但目标字段为空字符串（如 about:blank 的 hostname）也按 fallback 处理，
//     调用方可用第二参决定要 null 还是 ''，保留各处原有语义；
//   - 纯函数、不接触 Electron、不使用正则。

function resolveOr(raw, pick, fallback) {
  if (typeof raw !== 'string' || raw === '') return fallback;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return fallback;
  }
  let v;
  try {
    v = pick(u);
  } catch {
    return fallback;
  }
  if (v === '' || v == null) return fallback;
  return v;
}

// safeOrigin 取序列化源（scheme://host:port）。默认失败回 ''，需要区分"无法解析"
// 与"空源"的调用方可传 null。
function safeOrigin(raw, fallback = '') {
  return resolveOr(raw, (u) => u.origin, fallback);
}

// safeHostname 取小写主机名（不含端口、不含 IPv6 方括号）。
function safeHostname(raw, fallback = '') {
  return resolveOr(raw, (u) => u.hostname, fallback);
}

// safeHost 取 host（含端口）。
function safeHost(raw, fallback = '') {
  return resolveOr(raw, (u) => u.host, fallback);
}

// safeProtocol 取带冒号的协议（如 "https:"）。默认失败回 null，对齐历史调用方。
function safeProtocol(raw, fallback = null) {
  return resolveOr(raw, (u) => u.protocol, fallback);
}

module.exports = { safeOrigin, safeHostname, safeHost, safeProtocol };
