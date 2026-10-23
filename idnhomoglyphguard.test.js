'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IdnHomoglyphGuard, IDN_REASON } = require('./idnhomoglyphguard.js')

function reasons (d) {
  return new IdnHomoglyphGuard().evaluate(d).findings.map((f) => f.reason)
}

test('plain ascii domain safe', () => {
  assert.equal(new IdnHomoglyphGuard().evaluate('apple.com').safe, true)
})

test('cyrillic lookalike in latin word flagged', () => {
  // 'а' 用西里尔 U+0430
  const fake = '\u0430pple.com'
  const r = reasons(fake)
  assert.ok(r.includes(IDN_REASON.CYRILLIC_LOOKALIKE))
  assert.ok(r.includes(IDN_REASON.MIXED_SCRIPTS))
})

test('pure cyrillic label mixed-script rule nuanced', () => {
  // 整块都是西里尔：不算 latin 混用，但同形字单独不报（无拉丁并列时难以冒充拉丁词）
  const r = new IdnHomoglyphGuard().evaluate('\u0430\u0431\u0432.com')
  // .com 是独立 label；西里尔标签内无拉丁字母，不应报 MIXED_SCRIPTS
  assert.ok(!r.findings.some((f) => f.reason === IDN_REASON.MIXED_SCRIPTS))
})

test('greek omicron lookalike flagged', () => {
  const fake = 'g\u03BFogle.com'
  const r = reasons(fake)
  assert.ok(r.includes(IDN_REASON.GREEK_LOOKALIKE))
})

test('punycode label flagged for review', () => {
  assert.ok(reasons('xn--80ak6aa92e.com').includes(IDN_REASON.NON_ASCII_IN_PUNY))
})

test('digit letter ambiguity flagged', () => {
  assert.ok(reasons('g00gle.com').includes(IDN_REASON.DIGIT_LETTER_AMBIG))
})

test('normal numeric label not flagged', () => {
  // 纯数字 + 无 o/l 混淆字母
  const r = new IdnHomoglyphGuard().evaluate('123.test')
  assert.ok(!r.findings.some((f) => f.reason === IDN_REASON.DIGIT_LETTER_AMBIG))
})
