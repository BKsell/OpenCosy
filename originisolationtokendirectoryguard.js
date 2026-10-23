'use strict'

// originisolationtokendirectoryguard.js —— Origin/Agent 隔离关键词目录。
//
// 威胁模型：
//   Origin-Agent-Cluster、opaque origin、sandbox origin、discriminator 等隔离基线词，供跨源判定使用。纯字符查表，不用正则。

const OIT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const OIT_BLOCK = Object.freeze([
  'null',
  'opaque',
  'sandbox',
  'data:',
  'file:',
  'about:blank',
  'cross-origin',
  'opaque-origin',
])

const OIT_WARN = Object.freeze([
  'tuple',
  'ascii-serialization',
  'unicode-serialization',
  'discriminator',
  'site',
  'schemeful-same-site',
  'schemefully-same-site',
  'cross-site',
  'schemeful',
  'agent-cluster',
  'origin-agent-cluster',
  'coop',
  'coep',
  'corp',
  'isolation',
  'isolated',
])

const OIT_ALLOW = Object.freeze([
  'scheme',
  'host',
  'port',
  'domain',
  'origin',
  'same-origin',
  'https',
  'http',
  'ws',
  'wss',
  'default-port',
  'serialized',
  'tuple-origin',
  'prefix',
  'subdomain',
  'effective-domain',
  'site-for-cookies',
])

function OITLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function OITIn (list, v) {
  for (const x of list) { if (OITLower(x) === v) return true }
  return false
}

function OITClassify (tok) {
  const v = OITLower(String(tok == null ? '' : tok).trim())
  if (OITIn(OIT_BLOCK, v)) return OIT_CLASS.BLOCK
  if (OITIn(OIT_WARN, v)) return OIT_CLASS.WARN
  if (OITIn(OIT_ALLOW, v)) return OIT_CLASS.ALLOW
  return OIT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  OIT_CLASS: OIT_CLASS,
  OIT_BLOCK: OIT_BLOCK,
  OIT_WARN: OIT_WARN,
  OIT_ALLOW: OIT_ALLOW,
  OITClassify: OITClassify
})
