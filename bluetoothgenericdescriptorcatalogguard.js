'use strict'

// bluetoothgenericdescriptorcatalogguard.js —— 蓝牙通用 GATT 写入目录。
//
// 威胁模型：
//   requestDevice acceptAllDevices、写 characteristicDescriptor 可对周边设备下发控制，
//   应限定服务过滤。纯字符查表，不用正则。

const BTH_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const BTH_BLOCK = Object.freeze([
  'acceptalldevices',
  'writedescriptor',
  'writevalue-generic',
  'gatt-cross',
])

const BTH_WARN = Object.freeze([
  'notify-untrusted',
])

const BTH_ALLOW = Object.freeze([
  'services-filter',
])

function BTHLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function BTHIn (list, v) {
  for (const x of list) { if (BTHLower(x) === v) return true }
  return false
}

function BTHClassify (tok) {
  const v = BTHLower(String(tok == null ? '' : tok).trim())
  if (BTHIn(BTH_BLOCK, v)) return BTH_CLASS.BLOCK
  if (BTHIn(BTH_WARN, v)) return BTH_CLASS.WARN
  if (BTHIn(BTH_ALLOW, v)) return BTH_CLASS.ALLOW
  return BTH_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  BTH_CLASS: BTH_CLASS,
  BTH_BLOCK: BTH_BLOCK,
  BTH_WARN: BTH_WARN,
  BTH_ALLOW: BTH_ALLOW,
  BTHClassify: BTHClassify
})
