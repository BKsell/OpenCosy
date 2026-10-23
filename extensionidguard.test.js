'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ExtensionIdGuard, EI_REASON, eiValidId } = require('./extensionidguard.js')

function reasonsId (id) {
  return new ExtensionIdGuard().auditId(id).findings.map((f) => f.reason)
}
function reasonsUrl (url) {
  return new ExtensionIdGuard(['clients2.google.com', 'updates.own.test']).auditUpdateUrl(url).findings.map((f) => f.reason)
}

const valid32 = 'abcdefghijklmnopabcdefghijklmnop'

test('valid 32 a-p id', () => {
  assert.equal(eiValidId(valid32), null)
})

test('bad length', () => {
  assert.ok(reasonsId('abcdef').includes(EI_REASON.BAD_LENGTH))
})

test('bad charset', () => {
  assert.ok(reasonsId(valid32.slice(0, -1) + 'q').includes(EI_REASON.BAD_CHARSET))
})

test('uppercase a-p normalized and valid', () => {
  assert.equal(new ExtensionIdGuard().auditId(valid32.toUpperCase()).safe, true)
})

test('update url must be https', () => {
  assert.ok(reasonsUrl('http://clients2.google.com/update2/crx').includes(EI_REASON.UPDATE_SCHEME))
})

test('update host must be allowed', () => {
  assert.ok(reasonsUrl('https://evil.example/update.xml').includes(EI_REASON.UPDATE_HOST_NOT_ALLOWED))
})

test('allowed https update url safe', () => {
  assert.equal(new ExtensionIdGuard(['updates.own.test']).auditUpdateUrl('https://updates.own.test/v1.xml').safe, true)
})

test('manifest/derived id mismatch flagged', () => {
  const g = new ExtensionIdGuard()
  const r = g.auditIdMatch(valid32, valid32.slice(0, -1) + 'b')
  assert.ok(r.findings.some((f) => f.reason === EI_REASON.ID_MISMATCH))
})

test('matching valid ids pass', () => {
  assert.equal(new ExtensionIdGuard().auditIdMatch(valid32, valid32).safe, true)
})
