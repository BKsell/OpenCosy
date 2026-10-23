'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XDownloadOptionsGuard, XDO_REASON } = require('./xdownloadoptionsguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('noopen safe', () => {
  const g = new XDownloadOptionsGuard()
  assert.equal(g.evaluate('noopen').safe, true)
})

test('missing flagged by default', () => {
  const g = new XDownloadOptionsGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(XDO_REASON.MISSING))
})

test('missing ok when not required', () => {
  const g = new XDownloadOptionsGuard({ required: false })
  assert.equal(g.evaluate(null).safe, true)
})

test('empty flagged', () => {
  const g = new XDownloadOptionsGuard()
  assert.ok(reasonsOf(g.evaluate(' ')).includes(XDO_REASON.EMPTY))
})

test('wrong value', () => {
  const g = new XDownloadOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('open')).includes(XDO_REASON.NOT_NOOPEN))
})

test('multiple comma flagged', () => {
  const g = new XDownloadOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('noopen, noopen')).includes(XDO_REASON.MULTIPLE))
})

test('control char flagged', () => {
  const g = new XDownloadOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('noopen\r')).includes(XDO_REASON.CONTROL_CHAR))
})
