'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68H03Classify, E68H03_CLASS, E68H03_BLOCK, E68H03_WARN, E68H03_ALLOW } = require('./e68hex02uppercatalogguard.js')

test('E68H03 block classification', () => {
  for (const v of E68H03_BLOCK) assert.equal(E68H03Classify(v), E68H03_CLASS.BLOCK, v)
})

test('E68H03 warn classification', () => {
  for (const v of E68H03_WARN) assert.equal(E68H03Classify(v), E68H03_CLASS.WARN, v)
})

test('E68H03 allow classification', () => {
  for (const v of E68H03_ALLOW) assert.equal(E68H03Classify(v), E68H03_CLASS.ALLOW, v)
})

test('E68H03 unknown classification', () => {
  assert.equal(E68H03Classify('zzz-not-in-any-e68-catalog-77'), E68H03_CLASS.UNKNOWN)
})
