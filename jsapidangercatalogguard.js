'use strict'

// jsapidangercatalogguard.js —— 危险 JavaScript API 目录。
//
// 威胁模型：
//   渲染端把远端数据喂给 eval/Function/innerHTML/document.write 即 XSS/RCE。本模块审计代码片段或 API 调用名
//   集合，危险 API 阻断、安全写入 API 放行，纯字符匹配，不用正则。

const JSA_REASON = Object.freeze({
  BLOCK: 'jsapidangercatalog-input-hits-blocked-catalog',
  WARN: 'jsapidangercatalog-input-hits-review-catalog',
  PREFIX: 'jsapidangercatalog-input-hits-dangerous-prefix',
  EMPTY: 'jsapidangercatalog-input-is-empty'
})

const JSA_BLOCK = Object.freeze([
  'eval',
  'Function',
  'setTimeout(string)',
  'setInterval(string)',
  'execScript',
  'webkitRequestFileSystem',
  'document.write',
  'document.writeln',
  'XMLHttpRequest.sync',
  'importScripts',
  'createObjectURL',
  'uneval',
  'GeneratorFunction',
])

const JSA_WARN = Object.freeze([
  'postMessage',
  'requestFileSystem',
  'webkitResolveLocalFileSystemURL',
  'openDatabase',
  'indexedDB.deleteDatabase',
  'navigator.registerProtocolHandler',
  'showModalDialog',
])

const JSA_ALLOW = Object.freeze([
  'JSON.parse',
  'JSON.stringify',
  'addEventListener',
  'removeEventListener',
  'fetch',
  'queueMicrotask',
  'requestAnimationFrame',
  'structuredClone',
  'atob',
  'btoa',
])

const JSA_PREFIX_LIT = Object.freeze([
])
const JSA_PREFIX_REASON = Object.freeze([
])

function JSALower (x) {
  return x
}

function JSAIn (list, v) {
  for (const x of list) { if (JSALower(x) === v) return true }
  return false
}

function JSASplit (inStr) {
  const out = []
  let start = -1
  for (let i = 0; i <= inStr.length; i++) {
    const end = i === inStr.length
  let sep = false
    if (!end) { const c = inStr[i]; sep = c === ' ' || c === '\t' || c === '\n' || c === '\r' }
    if (end || sep) { if (start >= 0) { out.push(inStr.slice(start, i)); start = -1 } }
    else if (start < 0) { start = i } }
  return out
}

class JSAGuard {
  static get blockList () { return JSA_BLOCK }
  static get warnList () { return JSA_WARN }
  static get allowList () { return JSA_ALLOW }
  static get prefixLit () { return JSA_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: JSA_REASON.EMPTY }] }
    for (const tok of JSASplit(inStr)) {
      const cmp = JSALower(String(tok).trim())
      if (JSAIn(JSA_BLOCK, cmp)) findings.push({ reason: JSA_REASON.BLOCK, detail: cmp })
      else if (JSAIn(JSA_WARN, cmp)) findings.push({ reason: JSA_REASON.WARN, detail: cmp })
      for (let i = 0; i < JSA_PREFIX_LIT.length; i++) {
        const lit = JSA_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: JSA_REASON.PREFIX, detail: JSA_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  JSA_REASON: JSA_REASON,
  JSA_BLOCK: JSA_BLOCK,
  JSA_WARN: JSA_WARN,
  JSA_ALLOW: JSA_ALLOW,
  JSAGuard: JSAGuard
})
