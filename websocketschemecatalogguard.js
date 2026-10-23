'use strict'

// websocketschemecatalogguard.js —— WebSocket 传输方案目录。
//
// 威胁模型：
//   ws:// 明文可被中间人劫持与注入，应升级 wss://，soap/wamp/mqtt 等子协议跨域使用需复核。纯字符查表，不用正则。

const WSP_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WSP_BLOCK = Object.freeze([
  'ws',
  'http',
])

const WSP_WARN = Object.freeze([
  'soap',
  'wamp',
  'mqtt',
  'socket.io',
  'sockjs',
  'stomp',
])

const WSP_ALLOW = Object.freeze([
  'wss',
  'https',
])

function WSPLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WSPIn (list, v) {
  for (const x of list) { if (WSPLower(x) === v) return true }
  return false
}

function WSPClassify (tok) {
  const v = WSPLower(String(tok == null ? '' : tok).trim())
  if (WSPIn(WSP_BLOCK, v)) return WSP_CLASS.BLOCK
  if (WSPIn(WSP_WARN, v)) return WSP_CLASS.WARN
  if (WSPIn(WSP_ALLOW, v)) return WSP_CLASS.ALLOW
  return WSP_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WSP_CLASS: WSP_CLASS,
  WSP_BLOCK: WSP_BLOCK,
  WSP_WARN: WSP_WARN,
  WSP_ALLOW: WSP_ALLOW,
  WSPClassify: WSPClassify
})
