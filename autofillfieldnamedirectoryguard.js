'use strict'

// autofillfieldnamedirectoryguard.js —— 自动填充敏感字段名目录。
//
// 威胁模型：
//   username/email/cc-number/ssn/one-time-code 等自动填充字段需配自动完成策略与防覆盖。纯字符查表，不用正则。

const AFN_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const AFN_BLOCK = Object.freeze([
  'cc-number',
  'cc-name',
  'cc-exp',
  'cc-exp-month',
  'cc-exp-year',
  'cc-csc',
  'cc-type',
  'transaction-currency',
  'transaction-amount',
  'new-password',
  'one-time-code',
  'otp',
])

const AFN_WARN = Object.freeze([
  'username',
  'current-password',
  'email',
  'tel',
  'tel-country-code',
  'tel-national',
  'tel-area-code',
  'tel-local',
  'tel-extension',
  'address',
  'street-address',
  'address-line1',
  'address-line2',
  'address-line3',
  'address-level1',
  'address-level2',
  'address-level3',
  'address-level4',
  'country',
  'country-name',
  'postal-code',
  'name',
  'given-name',
  'additional-name',
  'family-name',
  'honorific-prefix',
  'honorific-suffix',
  'organization',
  'organization-title',
  'bday',
  'bday-day',
  'bday-month',
  'bday-year',
  'sex',
  'url',
  'photo',
  'impp',
  'language',
])

const AFN_ALLOW = Object.freeze([
  'off',
  'on',
  'section-',
  'shipping',
  'billing',
])

function AFNLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function AFNIn (list, v) {
  for (const x of list) { if (AFNLower(x) === v) return true }
  return false
}

function AFNClassify (tok) {
  const v = AFNLower(String(tok == null ? '' : tok).trim())
  if (AFNIn(AFN_BLOCK, v)) return AFN_CLASS.BLOCK
  if (AFNIn(AFN_WARN, v)) return AFN_CLASS.WARN
  if (AFNIn(AFN_ALLOW, v)) return AFN_CLASS.ALLOW
  return AFN_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  AFN_CLASS: AFN_CLASS,
  AFN_BLOCK: AFN_BLOCK,
  AFN_WARN: AFN_WARN,
  AFN_ALLOW: AFN_ALLOW,
  AFNClassify: AFNClassify
})
