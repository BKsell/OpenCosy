'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MSVClassify, MSV_CLASS, MSV_BLOCK, MSV_WARN, MSV_ALLOW } = require('./mixedschemevaluecatalogguard.js')

test('MSV block classification', () => {
  for (const v of MSV_BLOCK) assert.equal(MSVClassify(v), MSV_CLASS.BLOCK, v)
})

test('MSV warn classification', () => {
  for (const v of MSV_WARN) assert.equal(MSVClassify(v), MSV_CLASS.WARN, v)
})

test('MSV allow classification', () => {
  for (const v of MSV_ALLOW) assert.equal(MSVClassify(v), MSV_CLASS.ALLOW, v)
})

test('MSV unknown classification', () => {
  assert.equal(MSVClassify('zzz-not-in-catalog-7'), MSV_CLASS.UNKNOWN)
})
