'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PrototypePollutionGuard, PP_REASON, safeMerge } = require('./prototypepollutionguard.js')

test('clean config merges normally', () => {
  const g = new PrototypePollutionGuard()
  const r = g.merge({ a: 1 }, { b: 2, nested: { x: 1 } })
  assert.equal(r.safe, true)
  assert.deepEqual(r.result, { a: 1, b: 2, nested: { x: 1 } })
})

test('__proto__ payload audited and not applied', () => {
  const g = new PrototypePollutionGuard()
  const payload = JSON.parse('{"__proto__":{"polluted":"yes"}}')
  const r = g.merge({}, payload)
  assert.equal(r.safe, false)
  assert.ok(r.findings.some((f) => f.reason === PP_REASON.PROTO_KEY))
  assert.equal({}.polluted, undefined)
})

test('constructor.prototype audited and not applied', () => {
  const g = new PrototypePollutionGuard()
  const payload = JSON.parse('{"constructor":{"prototype":{"evil":1}}}')
  const r = g.merge({}, payload)
  assert.equal(r.safe, false)
  assert.ok(r.findings.some((f) => f.reason === PP_REASON.PROTO_KEY))
  assert.equal({}.evil, undefined)
})

test('nested proto key skipped', () => {
  const r = safeMerge({ keep: 1 }, JSON.parse('{"ok":{"__proto__":{"y":1}},"z":3}'))
  assert.equal(r.result.keep, 1)
  assert.equal(r.result.z, 3)
  assert.equal({}.y, undefined)
})

test('non-object sink rejected', () => {
  const r = safeMerge(null, { a: 1 })
  assert.equal(r.safe, false)
  assert.ok(r.findings.some((f) => f.reason === PP_REASON.NON_OBJECT_SINK))
})

test('deep nesting over limit flagged in audit', () => {
  let v = {}
  let cur = v
  for (let i = 0; i < 40; i++) {
    cur.d = {}
    cur = cur.d
  }
  const r = new PrototypePollutionGuard().audit(v, 32)
  assert.ok(r.findings.some((f) => f.reason === PP_REASON.TOO_DEEP))
})

test('merge over depth does not throw', () => {
  let src = { leaf: 1 }
  for (let i = 0; i < 40; i++) src = { d: src }
  assert.doesNotThrow(() => safeMerge({}, src, 32))
})

test('arrays are not treated as plain object sink', () => {
  const r = safeMerge([1, 2], { a: 1 })
  assert.equal(r.safe, false)
})
