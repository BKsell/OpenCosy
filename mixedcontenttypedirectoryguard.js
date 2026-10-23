'use strict'

// mixedcontenttypedirectoryguard.js —— 混合内容资源类型目录。
//
// 威胁模型：
//   https 页面里 script/iframe/worker/fetch 等 active 混合内容必须阻断，image/video 被动内容升级或警告。纯字符查表，不用正则。

const MCT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const MCT_BLOCK = Object.freeze([
  'script',
  'iframe',
  'object',
  'embed',
  'worker',
  'sharedworker',
  'serviceworker',
  'module',
  'import',
  'fetch',
  'websocket',
  'xmlhttprequest',
  'eventsource',
  'stylesheet',
  'css',
  'font',
])

const MCT_WARN = Object.freeze([
  'image',
  'img',
  'audio',
  'video',
  'source',
  'track',
  'picture',
  'svg',
  'favicon',
  'icon',
  'manifest',
  'prefetch',
  'preload',
  'preconnect',
  'dns-prefetch',
  'form',
  'navigator.sendBeacon',
  'beacon',
  'data',
  'data-uri',
  'blob',
  'download',
])

const MCT_ALLOW = Object.freeze([
  'upgrade-insecure-requests',
  'mixed-content',
  'block-all-mixed-content',
])

function MCTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function MCTIn (list, v) {
  for (const x of list) { if (MCTLower(x) === v) return true }
  return false
}

function MCTClassify (tok) {
  const v = MCTLower(String(tok == null ? '' : tok).trim())
  if (MCTIn(MCT_BLOCK, v)) return MCT_CLASS.BLOCK
  if (MCTIn(MCT_WARN, v)) return MCT_CLASS.WARN
  if (MCTIn(MCT_ALLOW, v)) return MCT_CLASS.ALLOW
  return MCT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  MCT_CLASS: MCT_CLASS,
  MCT_BLOCK: MCT_BLOCK,
  MCT_WARN: MCT_WARN,
  MCT_ALLOW: MCT_ALLOW,
  MCTClassify: MCTClassify
})
