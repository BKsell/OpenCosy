'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CertPinVerifyGuard, SPNP_REASON, spnpValidPin } = require('./certpinverifyguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

// 32 字节 sha256 的 base64 固定 44 字符（末尾 '='）。
function fakePin (seed) {
  let s = seed
  while (s.length < 43) s += 'A'
  return s.slice(0, 43) + '='
}

const PIN_A = fakePin('current')
const PIN_B = fakePin('backup000')
const PIN_R = fakePin('revoked00')

test('valid pin shape', () => {
  assert.equal(spnpValidPin(PIN_A), true)
  assert.equal(spnpValidPin('short='), false)
})

test('empty pin set rejected', () => {
  const r = new CertPinVerifyGuard({ pins: [] }).auditConfig()
  assert.ok(reasons(r).includes(SPNP_REASON.EMPTY_PIN_SET))
})

test('single pin lacks backup', () => {
  const r = new CertPinVerifyGuard({ pins: [PIN_A] }).auditConfig()
  assert.ok(reasons(r).includes(SPNP_REASON.NO_BACKUP_PIN))
})

test('malformed pin rejected', () => {
  const r = new CertPinVerifyGuard({ pins: [PIN_A, 'bad'] }).auditConfig()
  assert.ok(reasons(r).includes(SPNP_REASON.MALFORMED_PIN))
})

test('chain matching current pin passes', () => {
  const g = new CertPinVerifyGuard({ pins: [PIN_A, PIN_B] })
  const r = g.verify([fakePin('leaf-other'), PIN_A])
  assert.equal(r.safe, true)
  assert.equal(r.matched, PIN_A)
})

test('chain matching backup pin also passes', () => {
  const g = new CertPinVerifyGuard({ pins: [PIN_A, PIN_B] })
  assert.equal(g.verify([PIN_B]).safe, true)
})

test('no pin match fails', () => {
  const g = new CertPinVerifyGuard({ pins: [PIN_A, PIN_B] })
  assert.ok(reasons(g.verify([fakePin('nope')])).includes(SPNP_REASON.NO_MATCH))
})

test('empty chain fails', () => {
  const g = new CertPinVerifyGuard({ pins: [PIN_A, PIN_B] })
  assert.ok(reasons(g.verify([])).includes(SPNP_REASON.EMPTY_CHAIN))
})

test('revoked pin match fails even with current pin present', () => {
  const g = new CertPinVerifyGuard({ pins: [PIN_A, PIN_B], revoked: [PIN_R] })
  const r = g.verify([PIN_A, PIN_R])
  assert.equal(r.safe, false)
  assert.ok(reasons(r).includes(SPNP_REASON.REVOKED_PIN_MATCHED))
})
