'use strict'

// gamepadfingerprintcatalogguard.js —— 手柄指纹/输出目录。
//
// 威胁模型：
//   轮询 getGamepads 可枚举设备型号做指纹，vibrationActuator 可驱动硬件反馈，
//   应在用户手势后访问。纯字符查表，不用正则。

const GPD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const GPD_BLOCK = Object.freeze([
  'getgamepads-polling',
  'gamepad-id-entropy',
  'vibrationactuator',
])

const GPD_WARN = Object.freeze([
  'gamepaddisconnected-listen',
])

const GPD_ALLOW = Object.freeze([
  'user-gesture',
])

function GPDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function GPDIn (list, v) {
  for (const x of list) { if (GPDLower(x) === v) return true }
  return false
}

function GPDClassify (tok) {
  const v = GPDLower(String(tok == null ? '' : tok).trim())
  if (GPDIn(GPD_BLOCK, v)) return GPD_CLASS.BLOCK
  if (GPDIn(GPD_WARN, v)) return GPD_CLASS.WARN
  if (GPDIn(GPD_ALLOW, v)) return GPD_CLASS.ALLOW
  return GPD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  GPD_CLASS: GPD_CLASS,
  GPD_BLOCK: GPD_BLOCK,
  GPD_WARN: GPD_WARN,
  GPD_ALLOW: GPD_ALLOW,
  GPDClassify: GPDClassify
})
