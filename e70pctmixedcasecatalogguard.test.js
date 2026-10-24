'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PMCClassify, E70PMC_CLASS, E70PMC_BLOCK, E70PMC_WARN, E70PMC_ALLOW } = require('./e70pctmixedcasecatalogguard.js')

test('E70PMC block classification', () => {
  for (const v of E70PMC_BLOCK) assert.equal(E70PMCClassify(v), E70PMC_CLASS.BLOCK, v)
})

test('E70PMC warn classification', () => {
  for (const v of E70PMC_WARN) assert.equal(E70PMCClassify(v), E70PMC_CLASS.WARN, v)
})

test('E70PMC allow classification', () => {
  for (const v of E70PMC_ALLOW) assert.equal(E70PMCClassify(v), E70PMC_CLASS.ALLOW, v)
})

test('E70PMC unknown classification', () => {
  assert.equal(E70PMCClassify('zzz-not-in-any-e70-catalog-99'), E70PMC_CLASS.UNKNOWN)
})
