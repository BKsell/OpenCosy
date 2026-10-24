'use strict'

// e69caretnotationcatalogguard.js —— 终端插入符控制字符目录。
//
// 威胁模型：
//   ^@ ^[ ^? 等插入符记号在终端/串口协议中表示 NUL/ESC/DEL，写入终端可触发控制序列，
//   控制字符记号应阻断。纯字符查表，不用正则。

const E69CAR_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69CAR_BLOCK = Object.freeze([
  '^@',
  '^A',
  '^B',
  '^C',
  '^D',
  '^E',
  '^F',
  '^G',
  '^H',
  '^J',
  '^K',
  '^L',
  '^M',
  '^N',
  '^O',
  '^P',
  '^Q',
  '^R',
  '^S',
  '^T',
  '^U',
  '^V',
  '^W',
  '^X',
  '^Y',
  '^Z',
  '^[',
  '^\\',
  '^]',
  '^^',
  '^_',
  '^?',
])

const E69CAR_WARN = Object.freeze([
  '^I',
])

const E69CAR_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69CARLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69CARIn (list, v) {
  for (const x of list) { if (E69CARLower(x) === v) return true }
  return false
}

function E69CARClassify (tok) {
  const v = E69CARLower(String(tok == null ? '' : tok))
  if (E69CARIn(E69CAR_BLOCK, v)) return E69CAR_CLASS.BLOCK
  if (E69CARIn(E69CAR_WARN, v)) return E69CAR_CLASS.WARN
  if (E69CARIn(E69CAR_ALLOW, v)) return E69CAR_CLASS.ALLOW
  return E69CAR_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69CAR_CLASS: E69CAR_CLASS,
  E69CAR_BLOCK: E69CAR_BLOCK,
  E69CAR_WARN: E69CAR_WARN,
  E69CAR_ALLOW: E69CAR_ALLOW,
  E69CARClassify: E69CARClassify
})
