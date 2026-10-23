'use strict'

// batteryfingerprintcatalogguard.js —— 电池状态指纹目录。
//
// 威胁模型：
//   getBattery 的充电/电量/时间组合是稳定跨站指纹标识，
//   敏感/隐私模式应不读取。纯字符查表，不用正则。

const BAT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const BAT_BLOCK = Object.freeze([
  'getbattery',
  'chargingtime',
  'dischargingtime',
  'battery-level-entropy',
])

const BAT_WARN = Object.freeze([
  'charging-state',
])

const BAT_ALLOW = Object.freeze([
  'not-read',
])

function BATLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function BATIn (list, v) {
  for (const x of list) { if (BATLower(x) === v) return true }
  return false
}

function BATClassify (tok) {
  const v = BATLower(String(tok == null ? '' : tok).trim())
  if (BATIn(BAT_BLOCK, v)) return BAT_CLASS.BLOCK
  if (BATIn(BAT_WARN, v)) return BAT_CLASS.WARN
  if (BATIn(BAT_ALLOW, v)) return BAT_CLASS.ALLOW
  return BAT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  BAT_CLASS: BAT_CLASS,
  BAT_BLOCK: BAT_BLOCK,
  BAT_WARN: BAT_WARN,
  BAT_ALLOW: BAT_ALLOW,
  BATClassify: BATClassify
})
