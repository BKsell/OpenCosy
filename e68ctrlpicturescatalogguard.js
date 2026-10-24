'use strict'

// e68ctrlpicturescatalogguard.js —— 控制符图形表示码位目录。
//
// 威胁模型：
//   U+2400 起的控制符图形（␀␊）直观表示 NUL/换行，
//   不能因可视而放行，需按上下文拒绝。纯字符查表，不用正则。

const E68R29_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R29_BLOCK = Object.freeze([
])

const E68R29_WARN = Object.freeze([
  'U+2400',
  'U+2401',
  'U+2402',
  'U+2403',
  'U+2404',
  'U+2405',
  'U+2406',
  'U+2407',
  'U+2408',
  'U+2409',
  'U+240A',
  'U+240B',
  'U+240C',
  'U+240D',
  'U+240E',
  'U+240F',
  'U+2410',
  'U+2411',
  'U+2412',
  'U+2413',
  'U+2414',
  'U+2415',
  'U+2416',
  'U+2417',
  'U+2418',
  'U+2419',
  'U+241A',
  'U+241B',
  'U+241C',
  'U+241D',
  'U+241E',
  'U+241F',
  'U+2420',
  'U+2421',
  'U+2422',
  'U+2423',
  'U+2424',
  'U+2425',
  'U+2426',
  'U+2427',
  'U+2428',
  'U+2429',
  'U+242A',
  'U+242B',
  'U+242C',
  'U+242D',
  'U+242E',
  'U+242F',
  'U+2430',
  'U+2431',
  'U+2432',
  'U+2433',
  'U+2434',
  'U+2435',
  'U+2436',
  'U+2437',
  'U+2438',
  'U+2439',
  'U+243A',
  'U+243B',
  'U+243C',
  'U+243D',
  'U+243E',
  'U+243F',
])

const E68R29_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R29Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R29In (list, v) {
  for (const x of list) { if (E68R29Lower(x) === v) return true }
  return false
}

function E68R29Classify (tok) {
  const v = E68R29Lower(String(tok == null ? '' : tok).trim())
  if (E68R29In(E68R29_BLOCK, v)) return E68R29_CLASS.BLOCK
  if (E68R29In(E68R29_WARN, v)) return E68R29_CLASS.WARN
  if (E68R29In(E68R29_ALLOW, v)) return E68R29_CLASS.ALLOW
  return E68R29_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R29_CLASS: E68R29_CLASS,
  E68R29_BLOCK: E68R29_BLOCK,
  E68R29_WARN: E68R29_WARN,
  E68R29_ALLOW: E68R29_ALLOW,
  E68R29Classify: E68R29Classify
})
