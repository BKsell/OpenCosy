'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PMGClassify, PMG_CLASS, PMG_BLOCK, PMG_WARN, PMG_ALLOW } = require('./postmessagetargetcatalogguard.js')

test('PMG block classification', () => {
  for (const v of PMG_BLOCK) assert.equal(PMGClassify(v), PMG_CLASS.BLOCK, v)
})

test('PMG warn classification', () => {
  for (const v of PMG_WARN) assert.equal(PMGClassify(v), PMG_CLASS.WARN, v)
})

test('PMG allow classification', () => {
  for (const v of PMG_ALLOW) assert.equal(PMGClassify(v), PMG_CLASS.ALLOW, v)
})

test('PMG unknown classification', () => {
  assert.equal(PMGClassify('zzz-not-in-catalog-7'), PMG_CLASS.UNKNOWN)
})
