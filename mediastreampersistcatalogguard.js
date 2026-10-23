'use strict'

// mediastreampersistcatalogguard.js —— 摄像头/麦持续访问目录。
//
// 威胁模型：
//   getUserMedia 持久持有音视频轨道、getDisplayMedia 采集系统声音属高敏感，
//   应在用完后 stop 轨道并明示指示。纯字符查表，不用正则。

const MST_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const MST_BLOCK = Object.freeze([
  'getusermedia-persist',
  'getdisplaymedia-audio',
  'audio-system',
  'deviceid-exposed',
])

const MST_WARN = Object.freeze([
  'displaymedia-tab',
])

const MST_ALLOW = Object.freeze([
  'tracks-stopped',
  'user-grant',
])

function MSTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function MSTIn (list, v) {
  for (const x of list) { if (MSTLower(x) === v) return true }
  return false
}

function MSTClassify (tok) {
  const v = MSTLower(String(tok == null ? '' : tok).trim())
  if (MSTIn(MST_BLOCK, v)) return MST_CLASS.BLOCK
  if (MSTIn(MST_WARN, v)) return MST_CLASS.WARN
  if (MSTIn(MST_ALLOW, v)) return MST_CLASS.ALLOW
  return MST_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  MST_CLASS: MST_CLASS,
  MST_BLOCK: MST_BLOCK,
  MST_WARN: MST_WARN,
  MST_ALLOW: MST_ALLOW,
  MSTClassify: MSTClassify
})
