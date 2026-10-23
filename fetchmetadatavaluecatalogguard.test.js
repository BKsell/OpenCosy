'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FMDClassify, FMD_CLASS, FMD_BLOCK, FMD_WARN, FMD_ALLOW } = require('./fetchmetadatavaluecatalogguard.js')

test('FMD block classification', () => {
  for (const v of FMD_BLOCK) assert.equal(FMDClassify(v), FMD_CLASS.BLOCK, v)
})

test('FMD warn classification', () => {
  for (const v of FMD_WARN) assert.equal(FMDClassify(v), FMD_CLASS.WARN, v)
})

test('FMD allow classification', () => {
  for (const v of FMD_ALLOW) assert.equal(FMDClassify(v), FMD_CLASS.ALLOW, v)
})

test('FMD unknown classification', () => {
  assert.equal(FMDClassify('zzz-not-in-catalog-7'), FMD_CLASS.UNKNOWN)
})
