'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { LHIClassify, LHI_CLASS, LHI_BLOCK, LHI_WARN, LHI_ALLOW } = require('./linkhrefinjectioncatalogguard.js')

test('LHI block classification', () => {
  for (const v of LHI_BLOCK) assert.equal(LHIClassify(v), LHI_CLASS.BLOCK, v)
})

test('LHI warn classification', () => {
  for (const v of LHI_WARN) assert.equal(LHIClassify(v), LHI_CLASS.WARN, v)
})

test('LHI allow classification', () => {
  for (const v of LHI_ALLOW) assert.equal(LHIClassify(v), LHI_CLASS.ALLOW, v)
})

test('LHI unknown classification', () => {
  assert.equal(LHIClassify('zzz-not-in-catalog-7'), LHI_CLASS.UNKNOWN)
})
