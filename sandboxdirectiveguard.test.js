'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SandboxDirectiveGuard, parseSandboxTokens, SB_REASON } = require('./sandboxdirectiveguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('empty sandbox is fully restrictive and safe', () => {
  const g = new SandboxDirectiveGuard()
  const r = g.evaluate('')
  assert.equal(r.safe, true)
  assert.equal(r.fullyRestrictive, true)
})

test('allow-scripts + allow-same-origin flagged', () => {
  const g = new SandboxDirectiveGuard()
  const r = g.evaluate('allow-scripts allow-same-origin')
  assert.ok(reasonsOf(r).includes(SB_REASON.SCRIPTS_WITH_SAME_ORIGIN))
})

test('allow-scripts alone ok by default', () => {
  const g = new SandboxDirectiveGuard()
  assert.equal(g.evaluate('allow-scripts').safe, true)
})

test('top navigation flagged when policy rejects', () => {
  const g = new SandboxDirectiveGuard({ rejectTopNavigation: true })
  assert.ok(reasonsOf(g.evaluate('allow-top-navigation')).includes(SB_REASON.TOP_NAVIGATION))
  assert.ok(reasonsOf(g.evaluate('allow-top-navigation-by-user-activation')).includes(SB_REASON.TOP_NAVIGATION))
})

test('popups escape flagged when policy rejects', () => {
  const g = new SandboxDirectiveGuard({ rejectPopupsEscape: true })
  assert.ok(reasonsOf(g.evaluate('allow-popups-to-escape-sandbox')).includes(SB_REASON.POPUPS_ESCAPE))
})

test('unknown token ignored unless strict', () => {
  const g = new SandboxDirectiveGuard()
  assert.equal(g.evaluate('allow-scripts allow-bogus').safe, true)
  const g2 = new SandboxDirectiveGuard({ rejectUnknownTokens: true })
  assert.ok(reasonsOf(g2.evaluate('allow-bogus')).includes(SB_REASON.UNKNOWN_TOKEN))
})

test('parser collects set', () => {
  const p = parseSandboxTokens('allow-forms allow-modals')
  assert.equal(p.set['allow-forms'], true)
  assert.equal(p.set['allow-modals'], true)
})

test('case insensitive tokens', () => {
  const g = new SandboxDirectiveGuard()
  assert.ok(reasonsOf(g.evaluate('ALLOW-SCRIPTS ALLOW-SAME-ORIGIN')).includes(SB_REASON.SCRIPTS_WITH_SAME_ORIGIN))
})

test('control char flagged', () => {
  const g = new SandboxDirectiveGuard()
  assert.ok(reasonsOf(g.evaluate('allow-scripts\n')).includes(SB_REASON.CONTROL_CHAR))
})
