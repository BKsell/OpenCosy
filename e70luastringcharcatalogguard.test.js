'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70LSCClassify, E70LSC_CLASS, E70LSC_BLOCK, E70LSC_WARN, E70LSC_ALLOW } = require('./e70luastringcharcatalogguard.js')

test('E70LSC block classification', () => {
  for (const v of E70LSC_BLOCK) assert.equal(E70LSCClassify(v), E70LSC_CLASS.BLOCK, v)
})

test('E70LSC warn classification', () => {
  for (const v of E70LSC_WARN) assert.equal(E70LSCClassify(v), E70LSC_CLASS.WARN, v)
})

test('E70LSC allow classification', () => {
  for (const v of E70LSC_ALLOW) assert.equal(E70LSCClassify(v), E70LSC_CLASS.ALLOW, v)
})

test('E70LSC unknown classification', () => {
  assert.equal(E70LSCClassify('zzz-not-in-any-e70-catalog-99'), E70LSC_CLASS.UNKNOWN)
})
