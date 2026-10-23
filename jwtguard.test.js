'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { JwtGuard, JWT_REASON } = require('./jwtguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

function b64url (obj) {
  let s = Buffer.from(JSON.stringify(obj), 'utf8').toString('base64')
  let out = ''
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '+') out += '-'
    else if (s[i] === '/') out += '_'
    else if (s[i] === '=') continue
    else out += s[i]
  }
  return out
}

function token (header, payload, sig) {
  return b64url(header) + '.' + b64url(payload) + '.' + (sig === undefined ? 'sig' : sig)
}

const NOW = 1700000000

test('valid rs256 token passes', () => {
  const t = token({ alg: 'RS256', typ: 'JWT' }, { sub: 'u', iat: NOW, exp: NOW + 3600 })
  const r = new JwtGuard({ now: NOW }).inspect(t)
  assert.equal(r.safe, true, JSON.stringify(r.findings))
})

test('alg none flagged', () => {
  const t = token({ alg: 'none' }, { iat: NOW, exp: NOW + 10 }, '')
  const r = new JwtGuard({ now: NOW }).inspect(t)
  assert.ok(reasons(r).includes(JWT_REASON.ALG_NONE))
})

test('missing alg flagged', () => {
  const t = token({ typ: 'JWT' }, { iat: NOW, exp: NOW + 10 })
  assert.ok(reasons(new JwtGuard({ now: NOW }).inspect(t)).includes(JWT_REASON.ALG_MISSING))
})

test('unknown alg flagged', () => {
  const t = token({ alg: 'ROT13' }, { iat: NOW, exp: NOW + 10 })
  assert.ok(reasons(new JwtGuard({ now: NOW }).inspect(t)).includes(JWT_REASON.ALG_UNKNOWN))
})

test('expired flagged', () => {
  const t = token({ alg: 'RS256' }, { iat: NOW - 100, exp: NOW - 1 })
  assert.ok(reasons(new JwtGuard({ now: NOW }).inspect(t)).includes(JWT_REASON.EXP_EXPIRED))
})

test('missing exp flagged', () => {
  const t = token({ alg: 'RS256' }, { sub: 'u' })
  assert.ok(reasons(new JwtGuard({ now: NOW }).inspect(t)).includes(JWT_REASON.EXP_MISSING))
})

test('over-long lifetime flagged', () => {
  const t = token({ alg: 'RS256' }, { iat: NOW, exp: NOW + 999999 })
  assert.ok(reasons(new JwtGuard({ now: NOW, maxLifetime: 3600 }).inspect(t)).includes(JWT_REASON.EXP_TOO_FAR))
})

test('future iat flagged', () => {
  const t = token({ alg: 'RS256' }, { iat: NOW + 9999, exp: NOW + 9999 + 10 })
  assert.ok(reasons(new JwtGuard({ now: NOW }).inspect(t)).includes(JWT_REASON.IAT_IN_FUTURE))
})

test('remote key reference jku flagged', () => {
  const t = token({ alg: 'RS256', jku: 'https://evil/keys.json' }, { iat: NOW, exp: NOW + 10 })
  assert.ok(reasons(new JwtGuard({ now: NOW }).inspect(t)).includes(JWT_REASON.KEY_REFERENCE_URL))
})

test('two segments rejected', () => {
  assert.ok(reasons(new JwtGuard({ now: NOW }).inspect('a.b')).includes(JWT_REASON.BAD_SEGMENTS))
})

test('algorithm confusion detection', () => {
  const g = new JwtGuard({ now: NOW })
  assert.equal(g.isAlgorithmConfusion('asymmetric', { alg: 'HS256' }), true)
  assert.equal(g.isAlgorithmConfusion('asymmetric', { alg: 'RS256' }), false)
})
