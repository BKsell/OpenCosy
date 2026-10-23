'use strict'

// permissionnamecatalogguard.js —— 浏览器高风险权限名目录。
//
// 威胁模型：
//   磁力计/陀螺仪/光线传感器/bluetooth/usb/nfc 等强权限可指纹或侧信道，摄像头/麦克风/定位等需最小化，fullscreen 类低风险。纯字符查表，不用正则。

const PQN_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PQN_BLOCK = Object.freeze([
  'magnetometer',
  'ambient-light-sensor',
  'xr-spatial-tracking',
  'bluetooth',
  'usb',
  'nfc',
  'gyroscope',
  'accelerometer',
])

const PQN_WARN = Object.freeze([
  'camera',
  'microphone',
  'speaker',
  'midi',
  'geolocation',
  'notifications',
  'push',
  'clipboard-read',
  'clipboard-write',
  'screen-wake-lock',
  'device-info',
  'background-sync',
  'payment-handler',
  'window-management',
  'idle-detection',
])

const PQN_ALLOW = Object.freeze([
  'fullscreen',
  'autoplay',
  'persistent-storage',
  'keyboard-map',
  'local-fonts',
])

function PQNLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PQNIn (list, v) {
  for (const x of list) { if (PQNLower(x) === v) return true }
  return false
}

function PQNClassify (tok) {
  const v = PQNLower(String(tok == null ? '' : tok).trim())
  if (PQNIn(PQN_BLOCK, v)) return PQN_CLASS.BLOCK
  if (PQNIn(PQN_WARN, v)) return PQN_CLASS.WARN
  if (PQNIn(PQN_ALLOW, v)) return PQN_CLASS.ALLOW
  return PQN_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PQN_CLASS: PQN_CLASS,
  PQN_BLOCK: PQN_BLOCK,
  PQN_WARN: PQN_WARN,
  PQN_ALLOW: PQN_ALLOW,
  PQNClassify: PQNClassify
})
