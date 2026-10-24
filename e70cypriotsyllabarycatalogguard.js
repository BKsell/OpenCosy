'use strict'

// e70cypriotsyllabarycatalogguard.js —— 塞浦路斯音节文字目录。
//
// 威胁模型：
//   塞浦路斯音节文字为古文字，机器字段无任何正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70U08_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U08_BLOCK = Object.freeze([
  'U+10800',
  'U+10801',
  'U+10802',
  'U+10803',
  'U+10804',
  'U+10805',
  'U+10806',
  'U+10807',
  'U+10808',
  'U+10809',
  'U+1080A',
  'U+1080B',
  'U+1080C',
  'U+1080D',
  'U+1080E',
  'U+1080F',
  'U+10810',
  'U+10811',
  'U+10812',
  'U+10813',
  'U+10814',
  'U+10815',
  'U+10816',
  'U+10817',
  'U+10818',
  'U+10819',
  'U+1081A',
  'U+1081B',
  'U+1081C',
  'U+1081D',
  'U+1081E',
  'U+1081F',
  'U+10820',
  'U+10821',
  'U+10822',
  'U+10823',
  'U+10824',
  'U+10825',
  'U+10826',
  'U+10827',
  'U+10828',
  'U+10829',
  'U+1082A',
  'U+1082B',
  'U+1082C',
  'U+1082D',
  'U+1082E',
  'U+1082F',
  'U+10830',
  'U+10831',
  'U+10832',
  'U+10833',
  'U+10834',
  'U+10835',
  'U+10836',
  'U+10837',
  'U+10838',
  'U+10839',
  'U+1083A',
  'U+1083B',
  'U+1083C',
  'U+1083D',
  'U+1083E',
  'U+1083F',
])

const E70U08_WARN = Object.freeze([
])

const E70U08_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U08Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U08In (list, v) {
  for (const x of list) { if (E70U08Lower(x) === v) return true }
  return false
}

function E70U08Classify (tok) {
  const v = E70U08Lower(String(tok == null ? '' : tok))
  if (E70U08In(E70U08_BLOCK, v)) return E70U08_CLASS.BLOCK
  if (E70U08In(E70U08_WARN, v)) return E70U08_CLASS.WARN
  if (E70U08In(E70U08_ALLOW, v)) return E70U08_CLASS.ALLOW
  return E70U08_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U08_CLASS: E70U08_CLASS,
  E70U08_BLOCK: E70U08_BLOCK,
  E70U08_WARN: E70U08_WARN,
  E70U08_ALLOW: E70U08_ALLOW,
  E70U08Classify: E70U08Classify
})
