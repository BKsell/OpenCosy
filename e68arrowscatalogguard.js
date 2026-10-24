'use strict'

// e68arrowscatalogguard.js —— 箭头符号码位目录。
//
// 威胁模型：
//   类 ASCII 箭头/符号在日志与终端中可移动光标或伪造方向，
//   应按码点判定。纯字符查表，不用正则。

const E68R26_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R26_BLOCK = Object.freeze([
])

const E68R26_WARN = Object.freeze([
  'U+2190',
  'U+2191',
  'U+2192',
  'U+2193',
  'U+2194',
  'U+2195',
  'U+2196',
  'U+2197',
  'U+2198',
  'U+2199',
  'U+219A',
  'U+219B',
  'U+219C',
  'U+219D',
  'U+219E',
  'U+219F',
  'U+21A0',
  'U+21A1',
  'U+21A2',
  'U+21A3',
  'U+21A4',
  'U+21A5',
  'U+21A6',
  'U+21A7',
  'U+21A8',
  'U+21A9',
  'U+21AA',
  'U+21AB',
  'U+21AC',
  'U+21AD',
  'U+21AE',
  'U+21AF',
  'U+21B0',
  'U+21B1',
  'U+21B2',
  'U+21B3',
  'U+21B4',
  'U+21B5',
  'U+21B6',
  'U+21B7',
  'U+21B8',
  'U+21B9',
  'U+21BA',
  'U+21BB',
  'U+21BC',
  'U+21BD',
  'U+21BE',
  'U+21BF',
  'U+21C0',
  'U+21C1',
  'U+21C2',
  'U+21C3',
  'U+21C4',
  'U+21C5',
  'U+21C6',
  'U+21C7',
  'U+21C8',
  'U+21C9',
  'U+21CA',
  'U+21CB',
  'U+21CC',
  'U+21CD',
  'U+21CE',
  'U+21CF',
  'U+21D0',
  'U+21D1',
  'U+21D2',
  'U+21D3',
  'U+21D4',
  'U+21D5',
  'U+21D6',
  'U+21D7',
  'U+21D8',
  'U+21D9',
  'U+21DA',
  'U+21DB',
  'U+21DC',
  'U+21DD',
  'U+21DE',
  'U+21DF',
  'U+21E0',
  'U+21E1',
  'U+21E2',
  'U+21E3',
  'U+21E4',
  'U+21E5',
  'U+21E6',
  'U+21E7',
  'U+21E8',
  'U+21E9',
  'U+21EA',
  'U+21EB',
  'U+21EC',
  'U+21ED',
  'U+21EE',
  'U+21EF',
  'U+21F0',
  'U+21F1',
  'U+21F2',
  'U+21F3',
  'U+21F4',
  'U+21F5',
  'U+21F6',
  'U+21F7',
  'U+21F8',
  'U+21F9',
  'U+21FA',
  'U+21FB',
  'U+21FC',
  'U+21FD',
  'U+21FE',
  'U+21FF',
])

const E68R26_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R26Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R26In (list, v) {
  for (const x of list) { if (E68R26Lower(x) === v) return true }
  return false
}

function E68R26Classify (tok) {
  const v = E68R26Lower(String(tok == null ? '' : tok).trim())
  if (E68R26In(E68R26_BLOCK, v)) return E68R26_CLASS.BLOCK
  if (E68R26In(E68R26_WARN, v)) return E68R26_CLASS.WARN
  if (E68R26In(E68R26_ALLOW, v)) return E68R26_CLASS.ALLOW
  return E68R26_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R26_CLASS: E68R26_CLASS,
  E68R26_BLOCK: E68R26_BLOCK,
  E68R26_WARN: E68R26_WARN,
  E68R26_ALLOW: E68R26_ALLOW,
  E68R26Classify: E68R26Classify
})
