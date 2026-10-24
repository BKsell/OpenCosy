'use strict'

// e70controlpicturescatalogguard.js —— 控制符图形符号码位目录。
//
// 威胁模型：
//   ␀ ␊ ␤ 等控制符图形可让控制字符可视化混过人工/日志检查，机器字段应拒绝。纯字符查表，不用正则。

const E70T43_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T43_BLOCK = Object.freeze([
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

const E70T43_WARN = Object.freeze([
])

const E70T43_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T43Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T43In (list, v) {
  for (const x of list) { if (E70T43Lower(x) === v) return true }
  return false
}

function E70T43Classify (tok) {
  const v = E70T43Lower(String(tok == null ? '' : tok))
  if (E70T43In(E70T43_BLOCK, v)) return E70T43_CLASS.BLOCK
  if (E70T43In(E70T43_WARN, v)) return E70T43_CLASS.WARN
  if (E70T43In(E70T43_ALLOW, v)) return E70T43_CLASS.ALLOW
  return E70T43_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T43_CLASS: E70T43_CLASS,
  E70T43_BLOCK: E70T43_BLOCK,
  E70T43_WARN: E70T43_WARN,
  E70T43_ALLOW: E70T43_ALLOW,
  E70T43Classify: E70T43Classify
})
