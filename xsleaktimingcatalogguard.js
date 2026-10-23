'use strict'

// xsleaktimingcatalogguard.js —— XS-Leak 计时/侧信道原语目录。
//
// 威胁模型：
//   performance.now/SharedArrayBuffer/Atomics/cache/frame count/connection 等可用于跨站推断，敏感页面需加噪或隔离。纯字符查表，不用正则。

const XLT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const XLT_BLOCK = Object.freeze([
  'SharedArrayBuffer',
  'Atomics',
  'performance.now',
  'performance.timeOrigin',
  'performance.memory',
  'performance.webkitNow',
  'performance.mozNow',
  'performance.msNow',
  'performance.oNow',
  'performance.navigation',
  'performance.timing',
  'PerformanceObserver',
  'performance.measureUserAgentSpecificMemory',
  'performance.getEntries',
  'performance.getEntriesByType',
  'performance.getEntriesByName',
  'performance.mark',
  'performance.measure',
  'performance.clearMarks',
  'performance.clearMeasures',
  'performance.toJSON',
  'performance.eventCounts',
  'performance.setResourceTimingBufferSize',
  'performance.onresourcetimingbufferfull',
])

const XLT_WARN = Object.freeze([
  'Date.now',
  'new Date',
  'Date.getTime',
  'performance.markResourceTiming',
  'performance',
  'Worker',
  'navigator.hardwareConcurrency',
  'navigator.deviceMemory',
  'navigator.connection',
  'navigator.getBattery',
  'navigator.sendBeacon',
  'requestAnimationFrame',
  'setTimeout',
  'MessageChannel',
  'BroadcastChannel',
  'history.length',
  'window.length',
  'window.frames',
  'frameElement',
  'window.open',
  'window.screenX',
  'window.screenY',
  'window.outerWidth',
  'window.outerHeight',
])

const XLT_ALLOW = Object.freeze([
  'Date',
  'getTime',
  'now',
  'measure',
  'mark',
  'clearMarks',
  'clearMeasures',
  'hardwareConcurrency',
  'deviceMemory',
  'connection',
  'getBattery',
  'sendBeacon',
  'setInterval',
  'history',
  'length',
  'frames',
  'open',
  'screenX',
  'screenY',
  'outerWidth',
  'outerHeight',
  'eventCounts',
  'timeOrigin',
  'memory',
  'getEntries',
  'getEntriesByType',
  'getEntriesByName',
  'toJSON',
  'setResourceTimingBufferSize',
  'onresourcetimingbufferfull',
  'navigation',
  'timing',
  'measureUserAgentSpecificMemory',
])

function XLTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function XLTIn (list, v) {
  for (const x of list) { if (XLTLower(x) === v) return true }
  return false
}

function XLTClassify (tok) {
  const v = XLTLower(String(tok == null ? '' : tok).trim())
  if (XLTIn(XLT_BLOCK, v)) return XLT_CLASS.BLOCK
  if (XLTIn(XLT_WARN, v)) return XLT_CLASS.WARN
  if (XLTIn(XLT_ALLOW, v)) return XLT_CLASS.ALLOW
  return XLT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  XLT_CLASS: XLT_CLASS,
  XLT_BLOCK: XLT_BLOCK,
  XLT_WARN: XLT_WARN,
  XLT_ALLOW: XLT_ALLOW,
  XLTClassify: XLTClassify
})
