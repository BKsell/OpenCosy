'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TBRClassify, TBR_CLASS, TBR_BLOCK, TBR_WARN, TBR_ALLOW } = require('./targetblanknorelcatalogguard.js')

test('TBR block classification', () => {
  for (const v of TBR_BLOCK) assert.equal(TBRClassify(v), TBR_CLASS.BLOCK, v)
})

test('TBR warn classification', () => {
  for (const v of TBR_WARN) assert.equal(TBRClassify(v), TBR_CLASS.WARN, v)
})

test('TBR allow classification', () => {
  for (const v of TBR_ALLOW) assert.equal(TBRClassify(v), TBR_CLASS.ALLOW, v)
})

test('TBR unknown classification', () => {
  assert.equal(TBRClassify('zzz-not-in-catalog-7'), TBR_CLASS.UNKNOWN)
})
