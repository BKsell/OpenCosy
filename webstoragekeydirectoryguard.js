'use strict'

// webstoragekeydirectoryguard.js —— Web Storage 敏感键名目录。
//
// 威胁模型：
//   token/session/jwt/password/pii 等写入 localStorage 会被 XSS 长期读取，应改 httpOnly cookie。纯字符查表，不用正则。

const WSK_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WSK_BLOCK = Object.freeze([
  'token',
  'access_token',
  'access-token',
  'accesstoken',
  'id_token',
  'idtoken',
  'refresh_token',
  'refreshtoken',
  'jwt',
  'jwt_token',
  'session',
  'sessionid',
  'session_id',
  'session-token',
  'sid',
  'password',
  'passwd',
  'pwd',
  'secret',
  'apikey',
  'api_key',
  'api-key',
  'authorization',
  'auth',
  'credential',
  'credentials',
  'private_key',
  'privatekey',
  'privatetoken',
  'bearer',
  'otp',
  'one-time-code',
  'two-factor',
  '2fa',
  'mfa',
  'recovery',
  'backup-codes',
  'recoverycode',
  'ssn',
  'social',
  'creditcard',
  'cc-number',
  'cardnumber',
  'cvv',
  'pii',
  'personal',
  'private',
])

const WSK_WARN = Object.freeze([
  'user',
  'userid',
  'user_id',
  'uid',
  'uuid',
  'email',
  'phone',
  'profile',
  'account',
  'login',
  'authstate',
  'auth-state',
  'oauth',
  'oauth_state',
  'nonce',
  'state',
  'csrf',
  'xsrf',
  'csrftoken',
  'xcsrf',
  'remember',
  'rememberme',
  'cart',
  'order',
  'payment',
  'billing',
  'address',
  'location',
  'history',
])

const WSK_ALLOW = Object.freeze([
  'theme',
  'locale',
  'lang',
  'language',
  'timezone',
  'preferences',
  'settings',
  'ui',
  'layout',
  'sidebar',
  'dismissed',
  'seen',
  'banner',
  'notice',
  'consent',
  'drafts',
  'draft',
  'volume',
  'muted',
  'autoplay',
  'quality',
  'recent',
  'bookmarks',
  'tabs',
  'view',
  'grid',
  'filter',
  'sort',
])

function WSKLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WSKIn (list, v) {
  for (const x of list) { if (WSKLower(x) === v) return true }
  return false
}

function WSKClassify (tok) {
  const v = WSKLower(String(tok == null ? '' : tok).trim())
  if (WSKIn(WSK_BLOCK, v)) return WSK_CLASS.BLOCK
  if (WSKIn(WSK_WARN, v)) return WSK_CLASS.WARN
  if (WSKIn(WSK_ALLOW, v)) return WSK_CLASS.ALLOW
  return WSK_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WSK_CLASS: WSK_CLASS,
  WSK_BLOCK: WSK_BLOCK,
  WSK_WARN: WSK_WARN,
  WSK_ALLOW: WSK_ALLOW,
  WSKClassify: WSKClassify
})
