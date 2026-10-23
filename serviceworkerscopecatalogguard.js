'use strict'

// serviceworkerscopecatalogguard.js —— Service Worker scope/路由风险目录。
//
// 威胁模型：
//   scope=/ 过宽、importScripts 外域、navigationPreload 全部、updateViaCache=all 扩大 SW 控制面。纯字符查表，不用正则。

const SWS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SWS_BLOCK = Object.freeze([
  'scope=/',
  'all',
])

const SWS_WARN = Object.freeze([
  'importScripts',
  'navigationPreload',
  'updateViaCache',
  'foreign-fetch',
  'clients.claim',
  'skipWaiting',
  'self.registration',
  'register',
  'unregister',
  'getRegistration',
  'getRegistrations',
  'controller',
  'navigate',
  'focus',
  'openWindow',
  'postMessage',
  'BroadcastChannel',
  'MessageChannel',
  'periodicSync',
  'backgroundSync',
  'pushManager',
  'showNotification',
  'Cache',
  'caches',
  'clients.matchAll',
])

const SWS_ALLOW = Object.freeze([
  'none',
  'imports',
  'default',
])

function SWSLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SWSIn (list, v) {
  for (const x of list) { if (SWSLower(x) === v) return true }
  return false
}

function SWSClassify (tok) {
  const v = SWSLower(String(tok == null ? '' : tok).trim())
  if (SWSIn(SWS_BLOCK, v)) return SWS_CLASS.BLOCK
  if (SWSIn(SWS_WARN, v)) return SWS_CLASS.WARN
  if (SWSIn(SWS_ALLOW, v)) return SWS_CLASS.ALLOW
  return SWS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SWS_CLASS: SWS_CLASS,
  SWS_BLOCK: SWS_BLOCK,
  SWS_WARN: SWS_WARN,
  SWS_ALLOW: SWS_ALLOW,
  SWSClassify: SWSClassify
})
