'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MimeSniffGuard, MS_REASON, msDetectMagic, msLooksLikeHtml } = require('./mimesniffguard.js')

function reasons (i) {
  return new MimeSniffGuard().evaluate(i).findings.map((f) => f.reason)
}

function bytesOf (s) {
  const b = []
  for (let i = 0; i < s.length; i++) b.push(s.charCodeAt(i))
  return b
}

test('png magic detected', () => {
  assert.equal(msDetectMagic([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), 'image/png')
})

test('pdf magic detected', () => {
  assert.equal(msDetectMagic(bytesOf('%PDF-1.7')), 'application/pdf')
})

test('html prefix detected after bom and spaces', () => {
  assert.equal(msLooksLikeHtml([0xEF, 0xBB, 0xBF, 0x20, 0x3C, 0x21, 0x44, 0x4F, 0x43]), true)
})

test('nosniff missing flagged', () => {
  assert.ok(reasons({ contentType: 'image/png', bodyBytes: [] }).includes(MS_REASON.NOSNIFF_MISSING))
})

test('empty content type flagged', () => {
  assert.ok(reasons({ nosniff: true }).includes(MS_REASON.MIME_EMPTY))
})

test('mime magic mismatch flagged', () => {
  // 声明 text/plain，内容是 PNG 魔数
  const r = reasons({ contentType: 'text/plain', nosniff: true, bodyBytes: [0x89, 0x50, 0x4E, 0x47] })
  assert.ok(r.includes(MS_REASON.MIME_MAGIC_MISMATCH))
})

test('html served as text/plain flagged', () => {
  const r = reasons({ contentType: 'text/plain', nosniff: true, bodyBytes: bytesOf('<html><body>') })
  assert.ok(r.includes(MS_REASON.HTML_SERVED_AS_NON_HTML))
})

test('svg active flagged even with nosniff', () => {
  const r = reasons({ contentType: 'image/svg+xml', nosniff: true, bodyBytes: bytesOf('<svg ') })
  assert.ok(r.includes(MS_REASON.SVG_ACTIVE))
})

test('consistent png with nosniff safe', () => {
  const r = new MimeSniffGuard().evaluate({
    contentType: 'image/png', nosniff: true, bodyBytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
  })
  assert.equal(r.safe, true)
})
