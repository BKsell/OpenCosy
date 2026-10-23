'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { EHCClassify, EHC_CLASS, EHC_BLOCK, EHC_WARN, EHC_ALLOW } = require('./eventhandlercatalogguard.js')

test('EHC block classification', () => {
  for (const v of EHC_BLOCK) assert.equal(EHCClassify(v), EHC_CLASS.BLOCK, v)
})

test('EHC warn classification', () => {
  for (const v of EHC_WARN) assert.equal(EHCClassify(v), EHC_CLASS.WARN, v)
})

test('EHC allow classification', () => {
  for (const v of EHC_ALLOW) assert.equal(EHCClassify(v), EHC_CLASS.ALLOW, v)
})

test('EHC unknown classification', () => {
  assert.equal(EHCClassify('zzz-not-in-catalog-7'), EHC_CLASS.UNKNOWN)
})
