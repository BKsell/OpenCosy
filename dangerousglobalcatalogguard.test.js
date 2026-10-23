'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DJGClassify, DJG_CLASS, DJG_BLOCK, DJG_WARN, DJG_ALLOW } = require('./dangerousglobalcatalogguard.js')

test('DJG block classification', () => {
  for (const v of DJG_BLOCK) assert.equal(DJGClassify(v), DJG_CLASS.BLOCK, v)
})

test('DJG warn classification', () => {
  for (const v of DJG_WARN) assert.equal(DJGClassify(v), DJG_CLASS.WARN, v)
})

test('DJG allow classification', () => {
  for (const v of DJG_ALLOW) assert.equal(DJGClassify(v), DJG_CLASS.ALLOW, v)
})

test('DJG unknown classification', () => {
  assert.equal(DJGClassify('zzz-not-in-catalog-7'), DJG_CLASS.UNKNOWN)
})
