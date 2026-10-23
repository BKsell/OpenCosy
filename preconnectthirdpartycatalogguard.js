'use strict'

// preconnectthirdpartycatalogguard.js —— 预连接第三方目录。
//
// 威胁模型：
//   preconnect/dns-prefetch 第三方主机提前建连/泄露意图，prefetch 还会下载内容，
//   应限同注册域。纯字符查表，不用正则。

const LPC_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const LPC_BLOCK = Object.freeze([
  'preconnect-third',
  'dns-prefetch-third',
  'prefetch-third',
  'prerender-third',
])

const LPC_WARN = Object.freeze([
  'prefetch-cross',
])

const LPC_ALLOW = Object.freeze([
  'same-registrable',
])

function LPCLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function LPCIn (list, v) {
  for (const x of list) { if (LPCLower(x) === v) return true }
  return false
}

function LPCClassify (tok) {
  const v = LPCLower(String(tok == null ? '' : tok).trim())
  if (LPCIn(LPC_BLOCK, v)) return LPC_CLASS.BLOCK
  if (LPCIn(LPC_WARN, v)) return LPC_CLASS.WARN
  if (LPCIn(LPC_ALLOW, v)) return LPC_CLASS.ALLOW
  return LPC_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  LPC_CLASS: LPC_CLASS,
  LPC_BLOCK: LPC_BLOCK,
  LPC_WARN: LPC_WARN,
  LPC_ALLOW: LPC_ALLOW,
  LPCClassify: LPCClassify
})
