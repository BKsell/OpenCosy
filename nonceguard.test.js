'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { NonceGuard, NC_REASON, ncLowEntropy } = require('./nonceguard.js')

test('generated nonce length and uniqueness', () => {
  const g = new NonceGuard(() => new Array(22).fill(0))
  // 全 0 也能生成固定长度
  assert.equal(g.generate().length, 22)
  const vals = new Set()
  const rnd = (n) => {
    const b = []
    for (let i = 0; i < n; i++) b.push((Math.random() * 256) | 0)
    return b
  }
  const g2 = new NonceGuard(rnd)
  for (let i = 0; i < 50; i++) vals.add(g2.generate())
  assert.equal(vals.size, 50)
})

test('short nonce rejected', () => {
  const r = new NonceGuard().audit('abc')
  assert.ok(r.findings.some((f) => f.reason === NC_REASON.TOO_SHORT))
})

test('low-entropy repeated chars flagged', () => {
  assert.equal(ncLowEntropy('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), true)
})

test('strong random nonce passes current response', () => {
  const g = new NonceGuard()
  const n = g.generate()
  assert.equal(g.audit(n, 'current-response').safe, true)
})

test('same nonce in later response is reuse', () => {
  const g = new NonceGuard()
  const n = 'aZ3kP9qR7tYw2mB8xL5vN1cH6jF0dS4e'
  g.audit(n, 'current-response')
  const r = g.audit(n, 'later-response')
  assert.ok(r.findings.some((f) => f.reason === NC_REASON.REUSE))
})

test('nonce in url flagged', () => {
  const g = new NonceGuard()
  const n = 'aZ3kP9qR7tYw2mB8xL5vN1cH6jF0dS4e'
  assert.ok(g.audit(n, 'url').findings.some((f) => f.reason === NC_REASON.LEAKED_IN_URL))
})

test('nonce consumed twice flagged', () => {
  const g = new NonceGuard()
  const n = 'aZ3kP9qR7tYw2mB8xL5vN1cH6jF0dS4e'
  assert.equal(g.consume(n).safe, true)
  assert.equal(g.consume(n).safe, false)
})
