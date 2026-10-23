'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DPXClassify, DPX_CLASS, DPX_BLOCK, DPX_WARN, DPX_ALLOW } = require('./domparserxmlriskcatalogguard.js')

test('DPX block classification', () => {
  for (const v of DPX_BLOCK) assert.equal(DPXClassify(v), DPX_CLASS.BLOCK, v)
})

test('DPX warn classification', () => {
  for (const v of DPX_WARN) assert.equal(DPXClassify(v), DPX_CLASS.WARN, v)
})

test('DPX allow classification', () => {
  for (const v of DPX_ALLOW) assert.equal(DPXClassify(v), DPX_CLASS.ALLOW, v)
})

test('DPX unknown classification', () => {
  assert.equal(DPXClassify('zzz-not-in-catalog-7'), DPX_CLASS.UNKNOWN)
})
