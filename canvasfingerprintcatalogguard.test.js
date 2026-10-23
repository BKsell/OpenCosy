'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CFPClassify, CFP_CLASS, CFP_BLOCK, CFP_WARN, CFP_ALLOW } = require('./canvasfingerprintcatalogguard.js')

test('CFP block classification', () => {
  for (const v of CFP_BLOCK) assert.equal(CFPClassify(v), CFP_CLASS.BLOCK, v)
})

test('CFP warn classification', () => {
  for (const v of CFP_WARN) assert.equal(CFPClassify(v), CFP_CLASS.WARN, v)
})

test('CFP allow classification', () => {
  for (const v of CFP_ALLOW) assert.equal(CFPClassify(v), CFP_CLASS.ALLOW, v)
})

test('CFP unknown classification', () => {
  assert.equal(CFPClassify('zzz-not-in-catalog-7'), CFP_CLASS.UNKNOWN)
})
