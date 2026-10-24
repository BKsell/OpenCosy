'use strict'

// e70samaritancatalogguard.js —— 撒玛利亚文字码位目录。
//
// 威胁模型：
//   撒玛利亚文字罕用、渲染依赖专用字体，机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T07_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T07_BLOCK = Object.freeze([
  'U+0800',
  'U+0801',
  'U+0802',
  'U+0803',
  'U+0804',
  'U+0805',
  'U+0806',
  'U+0807',
  'U+0808',
  'U+0809',
  'U+080A',
  'U+080B',
  'U+080C',
  'U+080D',
  'U+080E',
  'U+080F',
  'U+0810',
  'U+0811',
  'U+0812',
  'U+0813',
  'U+0814',
  'U+0815',
  'U+0816',
  'U+0817',
  'U+0818',
  'U+0819',
  'U+081A',
  'U+081B',
  'U+081C',
  'U+081D',
  'U+081E',
  'U+081F',
  'U+0820',
  'U+0821',
  'U+0822',
  'U+0823',
  'U+0824',
  'U+0825',
  'U+0826',
  'U+0827',
  'U+0828',
  'U+0829',
  'U+082A',
  'U+082B',
  'U+082C',
  'U+082D',
  'U+082E',
  'U+082F',
  'U+0830',
  'U+0831',
  'U+0832',
  'U+0833',
  'U+0834',
  'U+0835',
  'U+0836',
  'U+0837',
  'U+0838',
  'U+0839',
  'U+083A',
  'U+083B',
  'U+083C',
  'U+083D',
  'U+083E',
  'U+083F',
])

const E70T07_WARN = Object.freeze([
])

const E70T07_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T07Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T07In (list, v) {
  for (const x of list) { if (E70T07Lower(x) === v) return true }
  return false
}

function E70T07Classify (tok) {
  const v = E70T07Lower(String(tok == null ? '' : tok))
  if (E70T07In(E70T07_BLOCK, v)) return E70T07_CLASS.BLOCK
  if (E70T07In(E70T07_WARN, v)) return E70T07_CLASS.WARN
  if (E70T07In(E70T07_ALLOW, v)) return E70T07_CLASS.ALLOW
  return E70T07_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T07_CLASS: E70T07_CLASS,
  E70T07_BLOCK: E70T07_BLOCK,
  E70T07_WARN: E70T07_WARN,
  E70T07_ALLOW: E70T07_ALLOW,
  E70T07Classify: E70T07Classify
})
