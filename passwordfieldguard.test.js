'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PasswordFieldGuard, PF_REASON } = require('./passwordfieldguard.js')

function reasons (f) {
  return new PasswordFieldGuard().evaluate(f).findings.map((x) => x.reason)
}

test('correct login password field safe', () => {
  const r = new PasswordFieldGuard().evaluate({
    autocomplete: 'current-password', pageScheme: 'https', spellcheck: false, maxLength: 128
  })
  assert.equal(r.safe, true)
})

test('missing autocomplete flagged', () => {
  assert.ok(reasons({ pageScheme: 'https' }).includes(PF_REASON.MISSING_AUTOCOMPLETE))
})

test('bogus autocomplete flagged', () => {
  assert.ok(reasons({ autocomplete: 'nope', pageScheme: 'https' }).includes(PF_REASON.BAD_AUTOCOMPLETE))
})

test('password on http page flagged', () => {
  assert.ok(reasons({ autocomplete: 'current-password', pageScheme: 'http' }).includes(PF_REASON.PASSWORD_ON_INSECURE_PAGE))
})

test('form action http flagged', () => {
  const r = reasons({ autocomplete: 'new-password', pageScheme: 'https', formActionScheme: 'http' })
  assert.ok(r.includes(PF_REASON.PASSWORD_ON_INSECURE_PAGE))
})

test('spellcheck enabled flagged', () => {
  assert.ok(reasons({ autocomplete: 'current-password', pageScheme: 'https', spellcheck: true }).includes(PF_REASON.SPELLCHECK_ON))
})

test('tiny maxlength flagged', () => {
  assert.ok(reasons({ autocomplete: 'current-password', pageScheme: 'https', maxLength: 4 }).includes(PF_REASON.WEAK_MAXLENGTH))
})

test('generous maxlength safe', () => {
  const r = new PasswordFieldGuard().evaluate({ autocomplete: 'new-password', pageScheme: 'https', maxLength: 256 })
  assert.equal(r.safe, true)
})
