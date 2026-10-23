'use strict'

// midisysexcatalogguard.js —— MIDI SysEx 权限目录。
//
// 威胁模型：
//   requestMIDIAccess(sysex=true) 可对硬件写入固件级指令，远超普通 MIDI，
//   应默认 sysex=false。纯字符查表，不用正则。

const MDI_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const MDI_BLOCK = Object.freeze([
  'sysex=true',
  'sysex-write',
  'firmware-write',
])

const MDI_WARN = Object.freeze([
  'midi-outputs',
])

const MDI_ALLOW = Object.freeze([
  'sysex=false',
])

function MDILower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function MDIIn (list, v) {
  for (const x of list) { if (MDILower(x) === v) return true }
  return false
}

function MDIClassify (tok) {
  const v = MDILower(String(tok == null ? '' : tok).trim())
  if (MDIIn(MDI_BLOCK, v)) return MDI_CLASS.BLOCK
  if (MDIIn(MDI_WARN, v)) return MDI_CLASS.WARN
  if (MDIIn(MDI_ALLOW, v)) return MDI_CLASS.ALLOW
  return MDI_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  MDI_CLASS: MDI_CLASS,
  MDI_BLOCK: MDI_BLOCK,
  MDI_WARN: MDI_WARN,
  MDI_ALLOW: MDI_ALLOW,
  MDIClassify: MDIClassify
})
