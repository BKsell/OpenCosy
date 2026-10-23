'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SABClassify, SAB_CLASS, SAB_BLOCK, SAB_WARN, SAB_ALLOW } = require('./sharedarraybuffercatalogguard.js')

test('SAB block classification', () => {
  for (const v of SAB_BLOCK) assert.equal(SABClassify(v), SAB_CLASS.BLOCK, v)
})

test('SAB warn classification', () => {
  for (const v of SAB_WARN) assert.equal(SABClassify(v), SAB_CLASS.WARN, v)
})

test('SAB allow classification', () => {
  for (const v of SAB_ALLOW) assert.equal(SABClassify(v), SAB_CLASS.ALLOW, v)
})

test('SAB unknown classification', () => {
  assert.equal(SABClassify('zzz-not-in-catalog-7'), SAB_CLASS.UNKNOWN)
})
