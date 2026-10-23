'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { UriComponentGuard, UC_REASON } = require('./uricomponentguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('healthy uri passes', () => {
  const r = new UriComponentGuard().evaluate({
    fullUrl: 'https://api.example.com/v1/version?os=windows',
    host: 'api.example.com'
  })
  assert.equal(r.safe, true)
})

test('valid port passes', () => {
  const r = new UriComponentGuard().evaluate({ fullUrl: 'https://h:8443/', host: 'h', port: '8443' })
  assert.equal(r.safe, true)
})

test('out-of-range and malformed ports flagged', () => {
  const g = new UriComponentGuard()
  for (const p of ['0', '70000', '-1', 'abc', '99999']) {
    const r = g.evaluate({ fullUrl: 'https://h:' + p + '/', host: 'h', port: p })
    assert.ok(reasons(r).includes(UC_REASON.PORT_INVALID), 'port ' + p)
  }
})

test('empty host flagged', () => {
  const r = new UriComponentGuard().evaluate({ fullUrl: 'https:///path', host: '' })
  assert.ok(reasons(r).includes(UC_REASON.EMPTY_HOST))
})

test('userinfo flagged', () => {
  const r = new UriComponentGuard().evaluate({ fullUrl: 'https://u:p@h/', host: 'h', hasUserInfo: true })
  assert.ok(reasons(r).includes(UC_REASON.USERINFO))
})

test('malformed percent encoding flagged', () => {
  const g = new UriComponentGuard()
  assert.ok(reasons(g.evaluate({ fullUrl: 'https://h/a%zz', host: 'h' })).includes(UC_REASON.BAD_PERCENT))
  assert.ok(reasons(g.evaluate({ fullUrl: 'https://h/a%2', host: 'h' })).includes(UC_REASON.BAD_PERCENT))
})

test('valid percent encoding passes', () => {
  const r = new UriComponentGuard().evaluate({ fullUrl: 'https://h/a%20b', host: 'h' })
  assert.equal(r.safe, true)
})

test('overlong label flagged', () => {
  let label = ''
  for (let i = 0; i < 70; i++) label += 'a'
  const r = new UriComponentGuard().evaluate({ fullUrl: 'https://' + label + '.com/', host: label + '.com' })
  assert.ok(reasons(r).includes(UC_REASON.HOST_OVERLONG))
})

test('ipv6 host skips label and multiple-port rules', () => {
  const r = new UriComponentGuard().evaluate({ fullUrl: 'https://[2001:db8::1]/', host: '2001:db8::1' })
  assert.equal(r.safe, true)
})

test('single residual colon in v4-style host flagged', () => {
  const r = new UriComponentGuard().evaluate({ fullUrl: 'https://1.2.3.4:80:90/', host: '1.2.3.4:80' })
  // '1.2.3.4:80' 含恰好一个冒号 → 多端口/残留端口
  assert.ok(reasons(r).includes(UC_REASON.MULTIPLE_PORTS))
})
