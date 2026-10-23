'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SandboxFrameGuard, SF2_REASON, sfTokens } = require('./sandboxframeguard.js')

function reasons (i) {
  return new SandboxFrameGuard().evaluate(i).findings.map((f) => f.reason)
}

test('empty sandbox string is maximally restrictive safe', () => {
  const r = new SandboxFrameGuard().evaluate({ thirdParty: true, sandbox: '' })
  assert.equal(r.safe, true)
})

test('whitespace-only sandbox treated empty safe', () => {
  assert.deepEqual(sfTokens('  '), [])
})

test('third party without sandbox flagged', () => {
  assert.ok(reasons({ thirdParty: true, sandbox: null }).includes(SF2_REASON.NO_SANDBOX))
})

test('scripts plus same-origin flagged', () => {
  assert.ok(reasons({ sandbox: 'allow-scripts allow-same-origin' }).includes(SF2_REASON.SCRIPTS_PLUS_SAMEORIGIN))
})

test('top navigation flagged', () => {
  assert.ok(reasons({ sandbox: 'allow-top-navigation' }).includes(SF2_REASON.TOP_NAVIGATION))
})

test('popups escape flagged', () => {
  assert.ok(reasons({ sandbox: 'allow-popups-to-escape-sandbox' }).includes(SF2_REASON.POPUPS_ESCAPE))
})

test('forms on display-only flagged', () => {
  assert.ok(reasons({ sandbox: 'allow-forms', purpose: 'display' }).includes(SF2_REASON.UNNEEDED_FORMS))
})

test('unknown token flagged', () => {
  assert.ok(reasons({ sandbox: 'allow-everything' }).includes(SF2_REASON.UNKNOWN_TOKEN))
})

test('restrictive widget safe', () => {
  const r = new SandboxFrameGuard().evaluate({ sandbox: 'allow-scripts', purpose: 'widget' })
  assert.equal(r.safe, true)
})
