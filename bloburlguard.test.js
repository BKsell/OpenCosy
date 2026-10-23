'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { BlobUrlGuard, BU_REASON } = require('./bloburlguard.js')

function reasons (i) {
  return new BlobUrlGuard().evaluate(i).findings.map((f) => f.reason)
}

test('https url unaffected', () => {
  assert.equal(new BlobUrlGuard().evaluate({ url: 'https://x.test/f' }).safe, true)
})

test('blob navigation flagged', () => {
  assert.ok(reasons({ url: 'blob:https://x.test/uuid', asNavigation: true }).includes(BU_REASON.BLOB_NAVIGATION))
})

test('data html navigation flagged executable', () => {
  const r = reasons({ url: 'data:text/html,<script>1</script>', asNavigation: true })
  assert.ok(r.includes(BU_REASON.DATA_EXECUTABLE_MIME))
})

test('data svg flagged', () => {
  assert.ok(reasons({ url: 'data:image/svg+xml;base64,PHN2Zw' }).includes(BU_REASON.DATA_EXECUTABLE_MIME))
})

test('data plain image mime safe', () => {
  assert.equal(new BlobUrlGuard().evaluate({ url: 'data:image/png;base64,AAAA' }).safe, true)
})

test('oversize data url flagged', () => {
  assert.ok(reasons({ url: 'data:text/plain,xxxx', dataMaxLength: 2 }).includes(BU_REASON.DATA_URL_OVERLONG))
})

test('blob origin mismatch flagged', () => {
  const r = reasons({ url: 'blob:https://a.test/u', pageOrigin: 'https://b.test', blobOrigin: 'https://a.test' })
  assert.ok(r.includes(BU_REASON.ORIGIN_MISMATCH))
})

test('unrevoked blob reported before unload', () => {
  const g = new BlobUrlGuard()
  g.created('blob:https://x.test/1', 'https://x.test')
  g.created('blob:https://x.test/2', 'https://x.test')
  g.revoked('blob:https://x.test/1')
  const r = g.auditBeforeUnload()
  assert.equal(r.safe, false)
  assert.deepEqual(r.leaked, ['blob:https://x.test/2'])
})

test('all revoked before unload safe', () => {
  const g = new BlobUrlGuard()
  g.created('blob:https://x.test/1', 'https://x.test')
  g.revoked('blob:https://x.test/1')
  assert.equal(g.auditBeforeUnload().safe, true)
})
