'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { RVGClassify, RVG_CLASS, RVG_BLOCK, RVG_WARN, RVG_ALLOW } = require('./referrervaluecatalogguard.js')

test('RVG block classification', () => {
  for (const v of RVG_BLOCK) assert.equal(RVGClassify(v), RVG_CLASS.BLOCK, v)
})

test('RVG warn classification', () => {
  for (const v of RVG_WARN) assert.equal(RVGClassify(v), RVG_CLASS.WARN, v)
})

test('RVG allow classification', () => {
  for (const v of RVG_ALLOW) assert.equal(RVGClassify(v), RVG_CLASS.ALLOW, v)
})

test('RVG unknown classification', () => {
  assert.equal(RVGClassify('zzz-not-in-catalog-7'), RVG_CLASS.UNKNOWN)
})
