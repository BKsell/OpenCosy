'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IpLiteralGuard, IL_REASON } = require('./ipliteralguard.js')

test('canonical public ip passes without ambiguity', () => {
  const r = new IpLiteralGuard().normalize('52.84.1.9')
  assert.equal(r.isIp, true)
  assert.equal(r.canonical, '52.84.1.9')
  assert.equal(r.class, 'public')
  assert.equal(r.reasons.length, 0)
})

test('decimal integer normalizes to loopback', () => {
  const r = new IpLiteralGuard().normalize('2130706433')
  assert.equal(r.canonical, '127.0.0.1')
  assert.equal(r.class, 'loopback')
  assert.ok(r.reasons.includes(IL_REASON.AMBIGUOUS_ENCODING))
})

test('octal 0177 normalizes to 127', () => {
  const r = new IpLiteralGuard().normalize('0177.0.0.1')
  assert.equal(r.canonical, '127.0.0.1')
  assert.ok(r.reasons.includes(IL_REASON.AMBIGUOUS_ENCODING))
})

test('hex segment normalizes', () => {
  const r = new IpLiteralGuard().normalize('0x7f.0.0.1')
  assert.equal(r.canonical, '127.0.0.1')
  assert.equal(r.class, 'loopback')
})

test('hex integer normalizes to loopback', () => {
  const r = new IpLiteralGuard().normalize('0x7f000001')
  assert.equal(r.canonical, '127.0.0.1')
})

test('ipv6 loopback forms', () => {
  const g = new IpLiteralGuard()
  for (const h of ['::1', '[::1]', '0:0:0:0:0:0:0:1']) {
    const r = g.normalize(h)
    assert.equal(r.isIp, true)
    assert.equal(r.class, 'loopback')
  }
})

test('ipv4-mapped private address', () => {
  const r = new IpLiteralGuard().normalize('::ffff:192.168.0.1')
  assert.equal(r.class, 'private')
  assert.ok(r.reasons.includes(IL_REASON.IPV6_MAPPED_INTERNAL))
})

test('ipv4-compatible loopback', () => {
  const r = new IpLiteralGuard().normalize('::127.0.0.1')
  assert.equal(r.class, 'loopback')
})

test('bracketed mapped metadata is link-local', () => {
  const r = new IpLiteralGuard().normalize('[::ffff:169.254.169.254]')
  assert.equal(r.class, 'linklocal')
})

test('hostname is not an ip literal', () => {
  const r = new IpLiteralGuard().normalize('api.example.com')
  assert.equal(r.isIp, false)
})

test('isInternal helper', () => {
  const g = new IpLiteralGuard()
  assert.equal(g.isInternal('127.0.0.1'), true)
  assert.equal(g.isInternal('10.1.2.3'), true)
  assert.equal(g.isInternal('8.8.8.8'), false)
})
