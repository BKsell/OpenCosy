'use strict'

// e70linearbcatalogguard.js —— 线形文字 B 平面目录。
//
// 威胁模型：
//   线形文字 B 为古文字，在任何机器字段都无正当用途，缺字体时不可见，
//   应直接拒绝。纯字符查表，不用正则。

const E70U00_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U00_BLOCK = Object.freeze([
  'U+10000',
  'U+10001',
  'U+10002',
  'U+10003',
  'U+10004',
  'U+10005',
  'U+10006',
  'U+10007',
  'U+10008',
  'U+10009',
  'U+1000A',
  'U+1000B',
  'U+1000C',
  'U+1000D',
  'U+1000E',
  'U+1000F',
  'U+10010',
  'U+10011',
  'U+10012',
  'U+10013',
  'U+10014',
  'U+10015',
  'U+10016',
  'U+10017',
  'U+10018',
  'U+10019',
  'U+1001A',
  'U+1001B',
  'U+1001C',
  'U+1001D',
  'U+1001E',
  'U+1001F',
  'U+10020',
  'U+10021',
  'U+10022',
  'U+10023',
  'U+10024',
  'U+10025',
  'U+10026',
  'U+10027',
  'U+10028',
  'U+10029',
  'U+1002A',
  'U+1002B',
  'U+1002C',
  'U+1002D',
  'U+1002E',
  'U+1002F',
  'U+10030',
  'U+10031',
  'U+10032',
  'U+10033',
  'U+10034',
  'U+10035',
  'U+10036',
  'U+10037',
  'U+10038',
  'U+10039',
  'U+1003A',
  'U+1003B',
  'U+1003C',
  'U+1003D',
  'U+1003E',
  'U+1003F',
  'U+10040',
  'U+10041',
  'U+10042',
  'U+10043',
  'U+10044',
  'U+10045',
  'U+10046',
  'U+10047',
  'U+10048',
  'U+10049',
  'U+1004A',
  'U+1004B',
  'U+1004C',
  'U+1004D',
  'U+1004E',
  'U+1004F',
  'U+10050',
  'U+10051',
  'U+10052',
  'U+10053',
  'U+10054',
  'U+10055',
  'U+10056',
  'U+10057',
  'U+10058',
  'U+10059',
  'U+1005A',
  'U+1005B',
  'U+1005C',
  'U+1005D',
  'U+1005E',
  'U+1005F',
  'U+10060',
  'U+10061',
  'U+10062',
  'U+10063',
  'U+10064',
  'U+10065',
  'U+10066',
  'U+10067',
  'U+10068',
  'U+10069',
  'U+1006A',
  'U+1006B',
  'U+1006C',
  'U+1006D',
  'U+1006E',
  'U+1006F',
  'U+10070',
  'U+10071',
  'U+10072',
  'U+10073',
  'U+10074',
  'U+10075',
  'U+10076',
  'U+10077',
  'U+10078',
  'U+10079',
  'U+1007A',
  'U+1007B',
  'U+1007C',
  'U+1007D',
  'U+1007E',
  'U+1007F',
])

const E70U00_WARN = Object.freeze([
])

const E70U00_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U00Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U00In (list, v) {
  for (const x of list) { if (E70U00Lower(x) === v) return true }
  return false
}

function E70U00Classify (tok) {
  const v = E70U00Lower(String(tok == null ? '' : tok))
  if (E70U00In(E70U00_BLOCK, v)) return E70U00_CLASS.BLOCK
  if (E70U00In(E70U00_WARN, v)) return E70U00_CLASS.WARN
  if (E70U00In(E70U00_ALLOW, v)) return E70U00_CLASS.ALLOW
  return E70U00_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U00_CLASS: E70U00_CLASS,
  E70U00_BLOCK: E70U00_BLOCK,
  E70U00_WARN: E70U00_WARN,
  E70U00_ALLOW: E70U00_ALLOW,
  E70U00Classify: E70U00Classify
})
