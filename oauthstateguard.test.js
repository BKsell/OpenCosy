'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OAuthStateGuard, OS_REASON } = require('./oauthstateguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

let clockNow = 1000
function g () {
  return new OAuthStateGuard({ now: () => clockNow, rng: (n) => { const a = []; for (let i = 0; i < n; i++) a.push((i * 7 + 3) & 63); return a } })
}

test('issue then consume succeeds', () => {
  const guard = g()
  const issued = guard.issue({ returnTo: '/home' })
  assert.equal(issued.safe, true)
  const r = guard.consume(issued.state, { returnTo: '/home' })
  assert.equal(r.safe, true)
})

test('unknown state rejected', () => {
  assert.ok(reasons(g().consume('nope')).includes(OS_REASON.STATE_UNKNOWN))
})

test('empty state rejected', () => {
  assert.ok(reasons(g().consume('')).includes(OS_REASON.STATE_EMPTY))
})

test('state one-time use enforced', () => {
  const guard = g()
  const issued = guard.issue()
  assert.equal(guard.consume(issued.state).safe, true)
  assert.ok(reasons(guard.consume(issued.state)).includes(OS_REASON.STATE_REUSED))
})

test('expired state rejected and removed', () => {
  const guard = g()
  const issued = guard.issue()
  clockNow += 20 * 60 * 1000
  assert.ok(reasons(guard.consume(issued.state)).includes(OS_REASON.STATE_EXPIRED))
  clockNow = 1000
})

test('context mismatch rejected', () => {
  const guard = g()
  const issued = guard.issue({ returnTo: '/a' })
  assert.ok(reasons(guard.consume(issued.state, { returnTo: '/b' })).includes(OS_REASON.CONTEXT_MISMATCH))
})

test('too-short generated state flagged', () => {
  const guard = new OAuthStateGuard({ stateBytes: 4, now: () => 1000 })
  assert.ok(reasons(guard.issue()).includes(OS_REASON.STATE_TOO_SHORT))
})
