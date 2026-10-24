'use strict'

// e70arabicsuppcatalogguard.js —— 阿拉伯文补充码位目录。
//
// 威胁模型：
//   阿拉伯文补充字符同样参与连写与双向排版，机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T04_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T04_BLOCK = Object.freeze([
  'U+0750',
  'U+0751',
  'U+0752',
  'U+0753',
  'U+0754',
  'U+0755',
  'U+0756',
  'U+0757',
  'U+0758',
  'U+0759',
  'U+075A',
  'U+075B',
  'U+075C',
  'U+075D',
  'U+075E',
  'U+075F',
  'U+0760',
  'U+0761',
  'U+0762',
  'U+0763',
  'U+0764',
  'U+0765',
  'U+0766',
  'U+0767',
  'U+0768',
  'U+0769',
  'U+076A',
  'U+076B',
  'U+076C',
  'U+076D',
  'U+076E',
  'U+076F',
  'U+0770',
  'U+0771',
  'U+0772',
  'U+0773',
  'U+0774',
  'U+0775',
  'U+0776',
  'U+0777',
  'U+0778',
  'U+0779',
  'U+077A',
  'U+077B',
  'U+077C',
  'U+077D',
  'U+077E',
  'U+077F',
])

const E70T04_WARN = Object.freeze([
])

const E70T04_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T04Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T04In (list, v) {
  for (const x of list) { if (E70T04Lower(x) === v) return true }
  return false
}

function E70T04Classify (tok) {
  const v = E70T04Lower(String(tok == null ? '' : tok))
  if (E70T04In(E70T04_BLOCK, v)) return E70T04_CLASS.BLOCK
  if (E70T04In(E70T04_WARN, v)) return E70T04_CLASS.WARN
  if (E70T04In(E70T04_ALLOW, v)) return E70T04_CLASS.ALLOW
  return E70T04_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T04_CLASS: E70T04_CLASS,
  E70T04_BLOCK: E70T04_BLOCK,
  E70T04_WARN: E70T04_WARN,
  E70T04_ALLOW: E70T04_ALLOW,
  E70T04Classify: E70T04Classify
})
