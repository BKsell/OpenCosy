'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const {
  PermissionsPolicyGuard,
  parseFeature,
  parsePermissionsPolicy,
  PP_REASON
} = require('./permissionspolicyguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('deny all sensitive via empty allowlist safe', () => {
  const g = new PermissionsPolicyGuard()
  const r = g.evaluate('camera=(), microphone=(), geolocation=()')
  assert.equal(r.safe, true)
  assert.equal(r.features[0].denied, true)
})

test('self only safe', () => {
  const g = new PermissionsPolicyGuard()
  assert.equal(g.evaluate('camera=(self)').safe, true)
})

test('wildcard flagged', () => {
  const g = new PermissionsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('camera=*')).includes(PP_REASON.WILDCARD))
})

test('omitted allowlist allows all', () => {
  const g = new PermissionsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('camera')).includes(PP_REASON.ALLOW_ALL_OMITTED))
})

test('third-party origin flagged', () => {
  const g = new PermissionsPolicyGuard()
  const r = g.evaluate('camera=(self "https://embed.example")')
  assert.ok(reasonsOf(r).includes(PP_REASON.THIRD_PARTY_ORIGIN))
  assert.equal(r.byName.camera.origins[0], 'https://embed.example')
})

test('single-quoted origin parsed', () => {
  const f = parseFeature("geolocation=('https://a.test')")
  assert.deepEqual(f.origins, ['https://a.test'])
  assert.equal(f.error, null)
})

test('unterminated quote syntax error', () => {
  const g = new PermissionsPolicyGuard()
  const r = g.evaluate('camera=(self "https://x)')
  assert.ok(reasonsOf(r).includes(PP_REASON.SYNTAX_ERROR))
})

test('non-parenthesized allowlist syntax error', () => {
  const g = new PermissionsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('camera=self')).includes(PP_REASON.SYNTAX_ERROR))
})

test('empty origin syntax error', () => {
  const g = new PermissionsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('camera=("")')).includes(PP_REASON.SYNTAX_ERROR))
})

test('missing and empty flagged', () => {
  const g = new PermissionsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(PP_REASON.MISSING))
  assert.ok(reasonsOf(g.evaluate('   ')).includes(PP_REASON.EMPTY))
})

test('control char flagged', () => {
  const g = new PermissionsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate("camera=()\nmic=()")).includes(PP_REASON.CONTROL_CHAR))
})

test('multiple features parsed count', () => {
  const p = parsePermissionsPolicy('camera=(), microphone=(self), usb=()')
  assert.equal(p.features.length, 3)
})

test('require deny sensitive policy', () => {
  const g = new PermissionsPolicyGuard({ requireDenySensitive: true })
  // camera 未出现 → 未显式禁用。
  assert.ok(reasonsOf(g.evaluate('microphone=()')).includes(PP_REASON.SENSITIVE_NOT_DISABLED))
  // 全部显式 () 才安全。
  // （只验证已列出的三个代表性敏感项由策略要求禁用，这里用单特性策略构造。）
  const g2 = new PermissionsPolicyGuard({
    requireDenySensitive: true,
    sensitive: { camera: true }
  })
  assert.ok(reasonsOf(g2.evaluate('camera=()')).length === 0)
})
