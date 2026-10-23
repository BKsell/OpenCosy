'use strict'

// permissionapitokendirectoryguard.js —— Permissions API 查询名目录。
//
// 威胁模型：
//   navigator.permissions.query 的权限名：摄像头/麦克风/MIDI/设备类强能力需复核，notifications/geolocation 按策略。纯字符查表，不用正则。

const PAT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PAT_BLOCK = Object.freeze([
  'camera',
  'microphone',
  'midi',
  'midi-sysex',
  'usb',
  'bluetooth',
  'serial',
  'hid',
  'nfc',
  'display-capture',
  'xr-spatial-tracking',
])

const PAT_WARN = Object.freeze([
  'geolocation',
  'push',
  'clipboard-read',
  'clipboard-write',
  'speaker-selection',
  'window-management',
  'local-fonts',
  'idle-detection',
  'screen-wake-lock',
  'accelerometer',
  'gyroscope',
  'magnetometer',
  'ambient-light-sensor',
  'payment',
  'persistent-storage',
  'storage-access',
  'top-level-storage-access',
  'background-fetch',
  'background-sync',
  'periodic-background-sync',
  'captured-surface-control',
  'keyboard-lock',
  'pointer-lock',
  'fullscreen',
])

const PAT_ALLOW = Object.freeze([
  'notifications',
])

function PATLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PATIn (list, v) {
  for (const x of list) { if (PATLower(x) === v) return true }
  return false
}

function PATClassify (tok) {
  const v = PATLower(String(tok == null ? '' : tok).trim())
  if (PATIn(PAT_BLOCK, v)) return PAT_CLASS.BLOCK
  if (PATIn(PAT_WARN, v)) return PAT_CLASS.WARN
  if (PATIn(PAT_ALLOW, v)) return PAT_CLASS.ALLOW
  return PAT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PAT_CLASS: PAT_CLASS,
  PAT_BLOCK: PAT_BLOCK,
  PAT_WARN: PAT_WARN,
  PAT_ALLOW: PAT_ALLOW,
  PATClassify: PATClassify
})
