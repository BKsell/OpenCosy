'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WACClassify, WAC_CLASS, WAC_BLOCK, WAC_WARN, WAC_ALLOW } = require('./webauthnrpidwildcardcatalogguard.js')

test('WAC block classification', () => {
  for (const v of WAC_BLOCK) assert.equal(WACClassify(v), WAC_CLASS.BLOCK, v)
})

test('WAC warn classification', () => {
  for (const v of WAC_WARN) assert.equal(WACClassify(v), WAC_CLASS.WARN, v)
})

test('WAC allow classification', () => {
  for (const v of WAC_ALLOW) assert.equal(WACClassify(v), WAC_CLASS.ALLOW, v)
})

test('WAC unknown classification', () => {
  assert.equal(WACClassify('zzz-not-in-catalog-7'), WAC_CLASS.UNKNOWN)
})
