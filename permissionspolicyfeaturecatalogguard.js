'use strict'

// permissionspolicyfeaturecatalogguard.js —— Permissions-Policy 特性目录。
//
// 威胁模型：
//   Permissions-Policy/allow 控制的强大特性（camera/geolocation/usb/interest-cohort 等）默认应禁用或按需放行。
//   纯字符查表，不用正则。

const PPF_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PPF_BLOCK = Object.freeze([
  'interest-cohort',
  'floc',
  'browsing-topics',
  'topics',
  'run-ad-auction',
  'join-ad-interest-group',
  'ad-attribution',
  'private-aggregation',
  'shared-storage',
  'private-state-token',
  'attribution-reporting',
  'unload',
])

const PPF_WARN = Object.freeze([
  'camera',
  'microphone',
  'geolocation',
  'midi',
  'midi-sysex',
  'usb',
  'bluetooth',
  'serial',
  'hid',
  'nfc',
  'payment',
  'credentials',
  'clipboard-read',
  'clipboard-write',
  'clipboard',
  'fullscreen',
  'pointer-lock',
  'keyboard-map',
  'gamepad',
  'window-management',
  'display-capture',
  'screen-wake-lock',
  'idle-detection',
  'local-fonts',
  'speaker-selection',
  'accelerometer',
  'gyroscope',
  'magnetometer',
  'ambient-light-sensor',
  'autoplay',
  'encrypted-media',
  'picture-in-picture',
  'xr-spatial-tracking',
  'publickey-credentials-get',
  'otp-credentials',
  'identity-credentials-get',
  'sync-xhr',
  'oversized-images',
  'unoptimized-images',
  'vertical-scroll',
  'focus-without-user-activation',
])

const PPF_ALLOW = Object.freeze([
  'self',
  'src',
  'none',
])

function PPFLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PPFIn (list, v) {
  for (const x of list) { if (PPFLower(x) === v) return true }
  return false
}

function PPFClassify (tok) {
  const v = PPFLower(String(tok == null ? '' : tok).trim())
  if (PPFIn(PPF_BLOCK, v)) return PPF_CLASS.BLOCK
  if (PPFIn(PPF_WARN, v)) return PPF_CLASS.WARN
  if (PPFIn(PPF_ALLOW, v)) return PPF_CLASS.ALLOW
  return PPF_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PPF_CLASS: PPF_CLASS,
  PPF_BLOCK: PPF_BLOCK,
  PPF_WARN: PPF_WARN,
  PPF_ALLOW: PPF_ALLOW,
  PPFClassify: PPFClassify
})
