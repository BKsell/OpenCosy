'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ZipBombGuard, ZB_REASON } = require('./zipbombguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('normal entry safe', () => {
  const g = new ZipBombGuard()
  assert.equal(g.auditEntry(800, 1000).safe, true)
})

test('high expansion ratio flagged', () => {
  const g = new ZipBombGuard({ maxRatio: 100 })
  const r = g.auditEntry(10, 50000)
  assert.ok(reasons(r).includes(ZB_REASON.RATIO_HIGH))
})

test('tiny compressed with large declared flagged', () => {
  const g = new ZipBombGuard()
  const r = g.auditEntry(0, 1000000)
  assert.ok(reasons(r).includes(ZB_REASON.RATIO_HIGH))
})

test('oversized declared entry flagged', () => {
  const g = new ZipBombGuard({ maxEntryDeclared: 1000 })
  const r = g.auditEntry(900, 5000)
  assert.ok(reasons(r).includes(ZB_REASON.DECLARED_HUGE))
})

test('accumulated total over limit flagged', () => {
  const g = new ZipBombGuard({ maxTotalBytes: 1000 })
  g.accountBytes(600)
  const r = g.accountBytes(500)
  assert.ok(reasons(r).includes(ZB_REASON.TOTAL_OVERFLOW))
})

test('entry count storm flagged', () => {
  const g = new ZipBombGuard({ maxEntries: 3 })
  g.auditEntry(1, 1)
  g.auditEntry(1, 1)
  g.auditEntry(1, 1)
  const r = g.auditEntry(1, 1)
  assert.ok(reasons(r).includes(ZB_REASON.TOO_MANY_ENTRIES))
})

test('negative size flagged', () => {
  const g = new ZipBombGuard()
  assert.ok(reasons(g.auditEntry(-1, 10)).includes(ZB_REASON.NEGATIVE_SIZE))
  assert.ok(reasons(g.accountBytes(-5)).includes(ZB_REASON.NEGATIVE_SIZE))
})

test('deep nesting flagged', () => {
  const g = new ZipBombGuard({ maxNestingDepth: 2 })
  assert.equal(g.auditNesting(2).safe, true)
  assert.equal(g.auditNesting(3).safe, false)
})

test('reset clears counters', () => {
  const g = new ZipBombGuard({ maxTotalBytes: 10 })
  g.accountBytes(20)
  g.reset()
  assert.equal(g.accountBytes(1).safe, true)
})
