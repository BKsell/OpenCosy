'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ClientRateLimitGuard, RateBucket, RL_REASON } = require('./clientratelimitguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('bucket allows within capacity then blocks', () => {
  let t = 0
  const b = new RateBucket(3, 1, 0)
  assert.equal(b.tryTake(1, 0), true)
  assert.equal(b.tryTake(2, 0), true)
  assert.equal(b.tryTake(1, 0), false)
  assert.equal(b.tryTake(1, 2), true)
})

test('invalid constructor throws', () => {
  assert.throws(() => new RateBucket(0, 1))
  assert.throws(() => new RateBucket(1, -1))
})

test('guard throttles a host', () => {
  let t = 0
  const g = new ClientRateLimitGuard({ capacity: 2, refillPerMs: 0, maxBurst: 10, now: () => t })
  assert.equal(g.acquire('h', 1).safe, true)
  assert.equal(g.acquire('h', 1).safe, true)
  const blocked = g.acquire('h', 1)
  assert.equal(blocked.safe, false)
  assert.ok(reasons(blocked).includes(RL_REASON.OVER_LIMIT))
})

test('different hosts have separate buckets', () => {
  let t = 0
  const g = new ClientRateLimitGuard({ capacity: 1, refillPerMs: 0, now: () => t })
  assert.equal(g.acquire('a').safe, true)
  assert.equal(g.acquire('b').safe, true)
})

test('burst cap enforced', () => {
  const g = new ClientRateLimitGuard({ capacity: 100, maxBurst: 2 })
  g.acquire('h')
  g.acquire('h')
  const r = g.acquire('h')
  assert.ok(reasons(r).includes(RL_REASON.BURST_TOO_HIGH))
})

test('release frees burst slot', () => {
  const g = new ClientRateLimitGuard({ capacity: 100, maxBurst: 1 })
  assert.equal(g.acquire('h').safe, true)
  g.release('h')
  assert.equal(g.acquire('h').safe, true)
})

test('refill over time restores tokens', () => {
  let t = 0
  const g = new ClientRateLimitGuard({ capacity: 2, refillPerMs: 1, maxBurst: 10, now: () => t })
  g.acquire('h', 2)
  assert.equal(g.acquire('h').safe, false)
  t = 5
  assert.equal(g.acquire('h').safe, true)
})
