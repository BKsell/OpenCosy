'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70SNCClassify, E70SNC_CLASS, E70SNC_BLOCK, E70SNC_WARN, E70SNC_ALLOW } = require('./e70sqlncharcatalogguard.js')

test('E70SNC block classification', () => {
  for (const v of E70SNC_BLOCK) assert.equal(E70SNCClassify(v), E70SNC_CLASS.BLOCK, v)
})

test('E70SNC warn classification', () => {
  for (const v of E70SNC_WARN) assert.equal(E70SNCClassify(v), E70SNC_CLASS.WARN, v)
})

test('E70SNC allow classification', () => {
  for (const v of E70SNC_ALLOW) assert.equal(E70SNCClassify(v), E70SNC_CLASS.ALLOW, v)
})

test('E70SNC unknown classification', () => {
  assert.equal(E70SNCClassify('zzz-not-in-any-e70-catalog-99'), E70SNC_CLASS.UNKNOWN)
})
