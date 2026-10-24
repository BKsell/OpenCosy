'use strict'

// e70geometricshapescatalogguard.js —— 几何形状码位目录。
//
// 威胁模型：
//   几何形状符号在机器字段无正当用途，可用于界面仿冒，
//   应直接拒绝。纯字符查表，不用正则。

const E70T47_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T47_BLOCK = Object.freeze([
  'U+25A0',
  'U+25A1',
  'U+25A2',
  'U+25A3',
  'U+25A4',
  'U+25A5',
  'U+25A6',
  'U+25A7',
  'U+25A8',
  'U+25A9',
  'U+25AA',
  'U+25AB',
  'U+25AC',
  'U+25AD',
  'U+25AE',
  'U+25AF',
  'U+25B0',
  'U+25B1',
  'U+25B2',
  'U+25B3',
  'U+25B4',
  'U+25B5',
  'U+25B6',
  'U+25B7',
  'U+25B8',
  'U+25B9',
  'U+25BA',
  'U+25BB',
  'U+25BC',
  'U+25BD',
  'U+25BE',
  'U+25BF',
  'U+25C0',
  'U+25C1',
  'U+25C2',
  'U+25C3',
  'U+25C4',
  'U+25C5',
  'U+25C6',
  'U+25C7',
  'U+25C8',
  'U+25C9',
  'U+25CA',
  'U+25CB',
  'U+25CC',
  'U+25CD',
  'U+25CE',
  'U+25CF',
  'U+25D0',
  'U+25D1',
  'U+25D2',
  'U+25D3',
  'U+25D4',
  'U+25D5',
  'U+25D6',
  'U+25D7',
  'U+25D8',
  'U+25D9',
  'U+25DA',
  'U+25DB',
  'U+25DC',
  'U+25DD',
  'U+25DE',
  'U+25DF',
  'U+25E0',
  'U+25E1',
  'U+25E2',
  'U+25E3',
  'U+25E4',
  'U+25E5',
  'U+25E6',
  'U+25E7',
  'U+25E8',
  'U+25E9',
  'U+25EA',
  'U+25EB',
  'U+25EC',
  'U+25ED',
  'U+25EE',
  'U+25EF',
  'U+25F0',
  'U+25F1',
  'U+25F2',
  'U+25F3',
  'U+25F4',
  'U+25F5',
  'U+25F6',
  'U+25F7',
  'U+25F8',
  'U+25F9',
  'U+25FA',
  'U+25FB',
  'U+25FC',
  'U+25FD',
  'U+25FE',
  'U+25FF',
])

const E70T47_WARN = Object.freeze([
])

const E70T47_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T47Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T47In (list, v) {
  for (const x of list) { if (E70T47Lower(x) === v) return true }
  return false
}

function E70T47Classify (tok) {
  const v = E70T47Lower(String(tok == null ? '' : tok))
  if (E70T47In(E70T47_BLOCK, v)) return E70T47_CLASS.BLOCK
  if (E70T47In(E70T47_WARN, v)) return E70T47_CLASS.WARN
  if (E70T47In(E70T47_ALLOW, v)) return E70T47_CLASS.ALLOW
  return E70T47_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T47_CLASS: E70T47_CLASS,
  E70T47_BLOCK: E70T47_BLOCK,
  E70T47_WARN: E70T47_WARN,
  E70T47_ALLOW: E70T47_ALLOW,
  E70T47Classify: E70T47Classify
})
