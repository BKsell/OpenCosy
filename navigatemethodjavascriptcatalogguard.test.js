'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { NMJClassify, NMJ_CLASS, NMJ_BLOCK, NMJ_WARN, NMJ_ALLOW } = require('./navigatemethodjavascriptcatalogguard.js')

test('NMJ block classification', () => {
  for (const v of NMJ_BLOCK) assert.equal(NMJClassify(v), NMJ_CLASS.BLOCK, v)
})

test('NMJ warn classification', () => {
  for (const v of NMJ_WARN) assert.equal(NMJClassify(v), NMJ_CLASS.WARN, v)
})

test('NMJ allow classification', () => {
  for (const v of NMJ_ALLOW) assert.equal(NMJClassify(v), NMJ_CLASS.ALLOW, v)
})

test('NMJ unknown classification', () => {
  assert.equal(NMJClassify('zzz-not-in-catalog-7'), NMJ_CLASS.UNKNOWN)
})
