'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')

const { PkceGuard, PK_REASON } = require('./pkceguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

function sha256b64url (v) {
  const raw = crypto.createHash('sha256').update(v, 'utf8').digest('base64')
  let out = ''
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === '+') out += '-'
    else if (raw[i] === '/') out += '_'
    else if (raw[i] === '=') continue
    else out += raw[i]
  }
  return out
}

const guard = new PkceGuard(sha256b64url)
const verifier = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW-._~01'
const challenge = sha256b64url(verifier)

test('matching S256 challenge passes', async () => {
  const r = await guard.verifyChallenge(verifier, challenge, 'S256')
  assert.equal(r.safe, true, JSON.stringify(r.findings))
})

test('wrong challenge rejected', async () => {
  const r = await guard.verifyChallenge(verifier, 'x'.repeat(43), 'S256')
  assert.ok(reasons(r).includes(PK_REASON.CHALLENGE_MISMATCH))
})

test('plain method rejected', async () => {
  const r = await guard.verifyChallenge(verifier, verifier, 'plain')
  assert.ok(reasons(r).includes(PK_REASON.METHOD_PLAIN))
})

test('unsupported method rejected', async () => {
  const r = await guard.verifyChallenge(verifier, challenge, 'RS256')
  assert.ok(reasons(r).includes(PK_REASON.METHOD_UNSUPPORTED))
})

test('short verifier rejected', () => {
  assert.ok(reasons(guard.validateVerifier('abc')).includes(PK_REASON.VERIFIER_TOO_SHORT))
})

test('long verifier rejected', () => {
  assert.ok(reasons(guard.validateVerifier('a'.repeat(129))).includes(PK_REASON.VERIFIER_TOO_LONG))
})

test('illegal verifier char rejected', () => {
  assert.ok(reasons(guard.validateVerifier('a'.repeat(43) + ' ')).includes(PK_REASON.VERIFIER_BAD_CHARS))
})

test('challenge bad length rejected', async () => {
  const r = await guard.verifyChallenge(verifier, 'short', 'S256')
  assert.ok(reasons(r).includes(PK_REASON.CHALLENGE_BAD_LEN))
})

test('missing verifier rejected', () => {
  assert.ok(reasons(guard.validateVerifier('')).includes(PK_REASON.VERIFIER_MISSING))
})

test('constructor requires hash function', () => {
  assert.throws(() => new PkceGuard())
})
