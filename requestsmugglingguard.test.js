'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { RequestSmugglingGuard, SM_REASON } = require('./requestsmugglingguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

function audit (hs) {
  return new RequestSmugglingGuard().audit(hs)
}

test('plain get safe', () => {
  assert.equal(audit([{ name: 'Host', value: 'h' }]).safe, true)
})

test('single content-length safe', () => {
  assert.equal(audit([{ name: 'content-length', value: '12' }]).safe, true)
})

test('CL and TE together flagged', () => {
  const r = audit([
    { name: 'Content-Length', value: '12' },
    { name: 'Transfer-Encoding', value: 'chunked' }
  ])
  assert.ok(reasons(r).includes(SM_REASON.CL_TE_BOTH))
})

test('multiple content-length flagged', () => {
  const r = audit([
    { name: 'Content-Length', value: '12' },
    { name: 'content-length', value: '30' }
  ])
  assert.ok(reasons(r).includes(SM_REASON.MULTIPLE_CL))
})

test('non-numeric content-length flagged', () => {
  const r = audit([{ name: 'content-length', value: '-1' }])
  assert.ok(reasons(r).includes(SM_REASON.BAD_CL))
})

test('unsupported TE token flagged', () => {
  const r = audit([{ name: 'transfer-encoding', value: 'gzip, chunked' }])
  assert.ok(reasons(r).includes(SM_REASON.BAD_TE))
})

test('obfuscated TE with tab flagged', () => {
  const r = audit([{ name: 'transfer-encoding', value: 'chunked\t' }])
  assert.ok(reasons(r).includes(SM_REASON.TE_OBSFUSCATED))
})

test('obfuscated TE with embedded CRLF flagged', () => {
  const r = audit([{ name: 'transfer-encoding', value: 'chunked\r\nX: y' }])
  assert.ok(reasons(r).includes(SM_REASON.TE_OBSFUSCATED))
})

test('case-insensitive header name matching', () => {
  const r = audit([{ name: 'TRANSFER-ENCODING', value: 'chunked' }])
  assert.equal(r.safe, true)
})
