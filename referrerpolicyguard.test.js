'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ReferrerPolicyGuard, parseReferrerTokens, RP_REASON } = require('./referrerpolicyguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('strict-origin-when-cross-origin safe', () => {
  const g = new ReferrerPolicyGuard()
  assert.equal(g.evaluate('strict-origin-when-cross-origin').safe, true)
})

test('no-referrer safe', () => {
  const g = new ReferrerPolicyGuard()
  assert.equal(g.evaluate('no-referrer').safe, true)
})

test('unsafe-url flagged', () => {
  const g = new ReferrerPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('unsafe-url')).includes(RP_REASON.UNSAFE_URL))
})

test('downgrade legacy flagged', () => {
  const g = new ReferrerPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('no-referrer-when-downgrade')).includes(RP_REASON.LEGACY_DOWNGRADE))
})

test('origin leaks cross-origin', () => {
  const g = new ReferrerPolicyGuard()
  const r = g.evaluate('origin')
  assert.ok(reasonsOf(r).includes(RP_REASON.CROSS_ORIGIN_LEAK))
})

test('missing flagged', () => {
  const g = new ReferrerPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(RP_REASON.MISSING))
})

test('empty flagged', () => {
  const g = new ReferrerPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('  ')).includes(RP_REASON.EMPTY))
})

test('unknown token flagged', () => {
  const g = new ReferrerPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('strict-origin, bogus')).includes(RP_REASON.UNKNOWN_TOKEN))
})

test('last recognized token wins', () => {
  const p = parseReferrerTokens('unsafe-url, no-referrer')
  assert.equal(p.tokens[p.tokens.length - 1], 'no-referrer')
  const g = new ReferrerPolicyGuard()
  // 最终生效 no-referrer，应安全（前面的宽值不决定最终行为）。
  assert.equal(g.evaluate('unsafe-url, no-referrer').safe, true)
})

test('all unknown tokens fails', () => {
  const g = new ReferrerPolicyGuard()
  assert.equal(g.evaluate('nonsense, garbage').safe, false)
})

test('control char flagged', () => {
  const g = new ReferrerPolicyGuard()
  assert.ok(reasonsOf(g.evaluate("no-referrer\r\n")).includes(RP_REASON.CONTROL_CHAR))
})
