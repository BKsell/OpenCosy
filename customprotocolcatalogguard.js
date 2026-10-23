'use strict'

// customprotocolcatalogguard.js —— 外部/自定义协议风险目录。
//
// 威胁模型：
//   注册/唤起 ms-*/intent/custom schemes 可触发本地程序，注册前需确认，未知 scheme 阻断，http/https/mailto 常规。纯字符查表，不用正则。

const CSH_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CSH_BLOCK = Object.freeze([
  'javascript',
  'vbscript',
  'data',
  'file',
  'blob',
  'filesystem',
  'about',
  'res',
  'ms-help',
  'mk',
  'shell',
  'jar',
  'netdoc',
  'gopher',
  'intent',
  'content',
  'content://',
  'file://',
])

const CSH_WARN = Object.freeze([
  'ms-windows-store',
  'ms-settings',
  'ms-cxh',
  'ms-actioncenter',
  'ms-appinstaller',
  'ms-mobileplans',
  'ms-phone',
  'ms-people',
  'ms-screensketch',
  'ms-soundrecorder',
  'ms-todo',
  'ms-whiteboard',
  'ms-yellowchat',
  'slack',
  'zoommtg',
  'zoomus',
  'msteams',
  'teams',
  'spotify',
  'itms',
  'itms-apps',
  'smb',
  'nfs',
  'ftp',
  'tel',
  'callto',
  'sms',
  'mms',
  'facetime',
  'facetime-audio',
  'webcal',
  'magnet',
  'ssh',
  'rdp',
  'vnc',
  'afp',
])

const CSH_ALLOW = Object.freeze([
  'http',
  'https',
  'mailto',
  'about:blank',
  'about:srcdoc',
])

function CSHLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CSHIn (list, v) {
  for (const x of list) { if (CSHLower(x) === v) return true }
  return false
}

function CSHClassify (tok) {
  const v = CSHLower(String(tok == null ? '' : tok).trim())
  if (CSHIn(CSH_BLOCK, v)) return CSH_CLASS.BLOCK
  if (CSHIn(CSH_WARN, v)) return CSH_CLASS.WARN
  if (CSHIn(CSH_ALLOW, v)) return CSH_CLASS.ALLOW
  return CSH_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CSH_CLASS: CSH_CLASS,
  CSH_BLOCK: CSH_BLOCK,
  CSH_WARN: CSH_WARN,
  CSH_ALLOW: CSH_ALLOW,
  CSHClassify: CSHClassify
})
