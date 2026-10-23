'use strict'

// sharedarraybuffercatalogguard.js —— SharedArrayBuffer 跨域隔离门槛目录。
//
// 威胁模型：
//   SharedArrayBuffer/Atomics 要求 COOP same-origin + COEP require-corp/credentialless，缺隔离即禁用。纯字符查表，不用正则。

const SAB_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SAB_BLOCK = Object.freeze([
  'SharedArrayBuffer',
  'Atomics',
  'Atomics.wait',
  'Atomics.notify',
  'Atomics.wake',
])

const SAB_WARN = Object.freeze([
  'unsafe-none',
  'unsafe-none-credentialless',
  'no-coop',
  'no-coep',
  'cross-origin',
  'cross-origin-embedder',
  'cross-origin-opener',
  'postMessage',
  'MessageChannel',
  'SharedWorker',
  'WebAssembly.Memory',
  'WebAssembly.Threads',
])

const SAB_ALLOW = Object.freeze([
  'same-origin',
  'same-origin-allow-popups',
  'require-corp',
  'credentialless',
  'crossOriginIsolated',
  'COOP',
  'COEP',
])

function SABLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SABIn (list, v) {
  for (const x of list) { if (SABLower(x) === v) return true }
  return false
}

function SABClassify (tok) {
  const v = SABLower(String(tok == null ? '' : tok).trim())
  if (SABIn(SAB_BLOCK, v)) return SAB_CLASS.BLOCK
  if (SABIn(SAB_WARN, v)) return SAB_CLASS.WARN
  if (SABIn(SAB_ALLOW, v)) return SAB_CLASS.ALLOW
  return SAB_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SAB_CLASS: SAB_CLASS,
  SAB_BLOCK: SAB_BLOCK,
  SAB_WARN: SAB_WARN,
  SAB_ALLOW: SAB_ALLOW,
  SABClassify: SABClassify
})
