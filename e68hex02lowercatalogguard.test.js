'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68H02Classify, E68H02_CLASS, E68H02_BLOCK, E68H02_WARN, E68H02_ALLOW } = require('./e68hex02lowercatalogguard.js')

test('E68H02 block classification', () => {
  for (const v of E68H02_BLOCK) assert.equal(E68H02Classify(v), E68H02_CLASS.BLOCK, v)
})

test('E68H02 warn classification', () => {
  for (const v of E68H02_WARN) assert.equal(E68H02Classify(v), E68H02_CLASS.WARN, v)
})

test('E68H02 allow classification', () => {
  for (const v of E68H02_ALLOW) assert.equal(E68H02Classify(v), E68H02_CLASS.ALLOW, v)
})

test('E68H02 unknown classification', () => {
  assert.equal(E68H02Classify('zzz-not-in-any-e68-catalog-77'), E68H02_CLASS.UNKNOWN)
})
