'use strict'

// browserschemedirectoryguard.js —— 浏览器 URI Scheme 风险分级目录。
//
// 威胁模型：
//   file/javascript/data/blob 可读本地或注入，外部 App/自定义协议用于唤起，http/https 常规。
//   纯字符查表（不含冒号），不用正则。

const BSD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const BSD_BLOCK = Object.freeze([
  'file',
  'javascript',
  'vbscript',
  'data',
  'blob',
  'filesystem',
  'about',
  'view-source',
  'wyciwyg',
  'res',
  'resource',
  'chrome',
  'chrome-untrusted',
  'chrome-search',
  'chrome-extension',
  'moz-extension',
  'ms-browser-extension',
  'devtools',
  'jar',
  'gopher',
  'ftp',
  'tftp',
  'telnet',
  'ldap',
  'ldaps',
  'rmi',
  'jndi',
  'dns',
  'nim',
])

const BSD_WARN = Object.freeze([
  'mailto',
  'tel',
  'sms',
  'callto',
  'mms',
  'mmsto',
  'facetime',
  'facetime-audio',
  'im',
  'sip',
  'sips',
  'xmpp',
  'skype',
  'zoommtg',
  'zoomus',
  'slack',
  'tg',
  'whatsapp',
  'weixin',
  'alipays',
  'alipay',
  'mqq',
  'msteam',
  'teams',
  'ms-meet',
  'webcal',
  'caldav',
  'carddav',
  'stun',
  'turn',
  'turns',
  'rtmp',
  'rtmps',
  'rtsp',
  'magnet',
  'thunder',
  'flashget',
  'qdl',
  'ed2k',
  'intent',
  'android-app',
  'ios',
  'itms',
  'itmss',
  'itms-apps',
  'itms-appst',
  'itmss-apps',
  'market',
  'app',
  'app-settings',
  'location',
  'maps',
  'geo',
  'openpgp4fpr',
  'keyparc',
  'lastpass',
  'snss',
  'ssh',
  'afp',
  'smb',
  'nfs',
  'vnc',
  'rdp',
  'ircs',
  'irc',
  'mumble',
  'teamspeak',
  'ventrilo',
  'steam',
  'battlenet',
  'glyph',
  'origin',
  'upstream',
  'custom',
  'external',
  'protocol',
])

const BSD_ALLOW = Object.freeze([
  'http',
  'https',
  'ws',
  'wss',
  'urn',
  'uuid',
  'urn:uuid',
])

function BSDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function BSDIn (list, v) {
  for (const x of list) { if (BSDLower(x) === v) return true }
  return false
}

function BSDClassify (tok) {
  const v = BSDLower(String(tok == null ? '' : tok).trim())
  if (BSDIn(BSD_BLOCK, v)) return BSD_CLASS.BLOCK
  if (BSDIn(BSD_WARN, v)) return BSD_CLASS.WARN
  if (BSDIn(BSD_ALLOW, v)) return BSD_CLASS.ALLOW
  return BSD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  BSD_CLASS: BSD_CLASS,
  BSD_BLOCK: BSD_BLOCK,
  BSD_WARN: BSD_WARN,
  BSD_ALLOW: BSD_ALLOW,
  BSDClassify: BSDClassify
})
