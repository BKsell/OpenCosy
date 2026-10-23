'use strict'

// trustedtypespolicydirectoryguard.js —— Trusted Types 策略与 sink 目录。
//
// 威胁模型：
//   Trusted Types 限制 innerHTML 等 sink；createHTML/default/duplicate 策略名与危险 sink 需受控。纯字符查表，不用正则。

const TTP_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const TTP_BLOCK = Object.freeze([
  'innerHTML',
  'outerHTML',
  'document.write',
  'document.writeln',
  'insertAdjacentHTML',
  'setHTMLUnsafe',
  'parseHTMLUnsafe',
  'createContextualFragment',
  'script',
  'script[src]',
  'iframe',
  'iframe[srcdoc]',
])

const TTP_WARN = Object.freeze([
  'createHTML',
  'createScript',
  'createScriptURL',
  'TrustedHTML',
  'TrustedScript',
  'TrustedScriptURL',
  'TrustedTypePolicyFactory',
  'TrustedTypePolicy',
  'trustedTypes',
  'createPolicy',
  'require-trusted-types-for',
  'require-trusted-types-for \'script\'',
  'trusted-types',
  'default',
  'duplicate',
  'createPolicy.default',
  'allowDuplicates',
  'isHTML',
  'isScript',
  'isScriptURL',
])

const TTP_ALLOW = Object.freeze([
  'empty',
  'none',
  'sanitizer',
  'DOMPurify',
  'report-only',
  'enforce',
  'policy-name',
  'sink',
  'source',
])

function TTPLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function TTPIn (list, v) {
  for (const x of list) { if (TTPLower(x) === v) return true }
  return false
}

function TTPClassify (tok) {
  const v = TTPLower(String(tok == null ? '' : tok).trim())
  if (TTPIn(TTP_BLOCK, v)) return TTP_CLASS.BLOCK
  if (TTPIn(TTP_WARN, v)) return TTP_CLASS.WARN
  if (TTPIn(TTP_ALLOW, v)) return TTP_CLASS.ALLOW
  return TTP_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  TTP_CLASS: TTP_CLASS,
  TTP_BLOCK: TTP_BLOCK,
  TTP_WARN: TTP_WARN,
  TTP_ALLOW: TTP_ALLOW,
  TTPClassify: TTPClassify
})
