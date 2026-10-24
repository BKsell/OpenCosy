'use strict'

// e69ipaextensionscatalogguard.js —— 国际音标扩展码位目录。
//
// 威胁模型：
//   音标字母中存在与拉丁小写近似的字形，混排可绕过基于字形的匹配，
//   标识符使用需复核。纯字符查表，不用正则。

const E69T03_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T03_BLOCK = Object.freeze([
])

const E69T03_WARN = Object.freeze([
  'U+0250',
  'U+0251',
  'U+0252',
  'U+0253',
  'U+0254',
  'U+0255',
  'U+0256',
  'U+0257',
  'U+0258',
  'U+0259',
  'U+025A',
  'U+025B',
  'U+025C',
  'U+025D',
  'U+025E',
  'U+025F',
  'U+0260',
  'U+0261',
  'U+0262',
  'U+0263',
  'U+0264',
  'U+0265',
  'U+0266',
  'U+0267',
  'U+0268',
  'U+0269',
  'U+026A',
  'U+026B',
  'U+026C',
  'U+026D',
  'U+026E',
  'U+026F',
  'U+0270',
  'U+0271',
  'U+0272',
  'U+0273',
  'U+0274',
  'U+0275',
  'U+0276',
  'U+0277',
  'U+0278',
  'U+0279',
  'U+027A',
  'U+027B',
  'U+027C',
  'U+027D',
  'U+027E',
  'U+027F',
  'U+0280',
  'U+0281',
  'U+0282',
  'U+0283',
  'U+0284',
  'U+0285',
  'U+0286',
  'U+0287',
  'U+0288',
  'U+0289',
  'U+028A',
  'U+028B',
  'U+028C',
  'U+028D',
  'U+028E',
  'U+028F',
  'U+0290',
  'U+0291',
  'U+0292',
  'U+0293',
  'U+0294',
  'U+0295',
  'U+0296',
  'U+0297',
  'U+0298',
  'U+0299',
  'U+029A',
  'U+029B',
  'U+029C',
  'U+029D',
  'U+029E',
  'U+029F',
  'U+02A0',
  'U+02A1',
  'U+02A2',
  'U+02A3',
  'U+02A4',
  'U+02A5',
  'U+02A6',
  'U+02A7',
  'U+02A8',
  'U+02A9',
  'U+02AA',
  'U+02AB',
  'U+02AC',
  'U+02AD',
  'U+02AE',
  'U+02AF',
])

const E69T03_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T03Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T03In (list, v) {
  for (const x of list) { if (E69T03Lower(x) === v) return true }
  return false
}

function E69T03Classify (tok) {
  const v = E69T03Lower(String(tok == null ? '' : tok))
  if (E69T03In(E69T03_BLOCK, v)) return E69T03_CLASS.BLOCK
  if (E69T03In(E69T03_WARN, v)) return E69T03_CLASS.WARN
  if (E69T03In(E69T03_ALLOW, v)) return E69T03_CLASS.ALLOW
  return E69T03_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T03_CLASS: E69T03_CLASS,
  E69T03_BLOCK: E69T03_BLOCK,
  E69T03_WARN: E69T03_WARN,
  E69T03_ALLOW: E69T03_ALLOW,
  E69T03Classify: E69T03Classify
})
