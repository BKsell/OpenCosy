'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const {
  ContentSecurityPolicyGuard,
  parseCsp,
  cspClassifySources,
  cspSourceKind,
  CSP_REASON
} = require('./contentsecuritypolicyguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

const STRICT = [
  "default-src 'self'",
  "script-src 'self' 'nonce-x9'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  'upgrade-insecure-requests'
].join('; ')

test('strict policy is safe', () => {
  const g = new ContentSecurityPolicyGuard()
  const r = g.evaluate(STRICT)
  assert.equal(r.safe, true, JSON.stringify(r.findings))
})

test('missing csp flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(CSP_REASON.MISSING))
})

test('empty csp flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('  ')).includes(CSP_REASON.EMPTY))
})

test('unsafe-inline flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.UNSAFE_INLINE))
})

test('unsafe-eval flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.UNSAFE_EVAL))
})

test('wildcard script src flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.WILDCARD_SOURCE))
})

test('data uri script source flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.DATA_OR_BLOB_SCRIPT))
})

test('http scheme script source flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src http:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.SCHEME_SOURCE))
})

test('script-src missing entirely flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  assert.ok(reasonsOf(g.evaluate("img-src 'self'")).includes(CSP_REASON.SCRIPT_SRC_MISSING))
})

test('default-src serves as script fallback', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  // default-src 'self' 对脚本不算 wildcard/inline，脚本面应无致命项，整体 safe。
  assert.equal(g.evaluate(csp).safe, true)
})

test('object-src unrestricted flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'nonce-a'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.OBJECT_SRC_UNRESTRICTED))
})

test('object-src wildcard flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'nonce-a'; object-src *; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.OBJECT_SRC_UNRESTRICTED))
})

test('base-uri missing flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'nonce-a'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.BASE_URI_MISSING))
})

test('frame-ancestors missing flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'nonce-a'; object-src 'none'; base-uri 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.FRAME_ANCESTORS_MISSING))
})

test('form-action missing flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'nonce-a'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.FORM_ACTION_MISSING))
})

test('duplicate directive flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = STRICT + "; object-src 'self'"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.DUPLICATE_DIRECTIVE))
})

test('strict-dynamic without nonce/hash flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.ok(reasonsOf(g.evaluate(csp)).includes(CSP_REASON.STRICT_DYNAMIC_CONFLICT))
})

test('strict-dynamic with nonce is acceptable', () => {
  const g = new ContentSecurityPolicyGuard()
  const csp = "script-src 'nonce-a' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  assert.equal(g.evaluate(csp).safe, true)
})

test('parse duplicate keeps first', () => {
  const p = parseCsp("object-src 'none'; object-src *")
  assert.equal(p.byName['object-src'].tokens[0], "'none'")
  assert.ok(p.duplicates.includes('object-src'))
})

test('classify sources', () => {
  const p = parseCsp("script-src 'self' 'nonce-z' 'unsafe-inline'")
  const k = cspClassifySources(p.byName['script-src'])
  assert.equal(k.self, true)
  assert.equal(k.nonce, true)
  assert.equal(k.unsafeInline, true)
})

test('source kind mapping', () => {
  assert.equal(cspSourceKind('*'), 'wildcard')
  assert.equal(cspSourceKind('https:'), 'scheme-https')
  assert.equal(cspSourceKind('data:'), 'data-blob-scheme')
  assert.equal(cspSourceKind("'unsafe-eval'"), 'unsafe-evalish')
})

test('control char flagged', () => {
  const g = new ContentSecurityPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(STRICT + '\n')).includes(CSP_REASON.CONTROL_CHAR))
})
