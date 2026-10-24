'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R26Classify, E68R26_CLASS, E68R26_BLOCK, E68R26_WARN, E68R26_ALLOW } = require('./e68arrowscatalogguard.js')

test('E68R26 block classification', () => {
  for (const v of E68R26_BLOCK) assert.equal(E68R26Classify(v), E68R26_CLASS.BLOCK, v)
})

test('E68R26 warn classification', () => {
  for (const v of E68R26_WARN) assert.equal(E68R26Classify(v), E68R26_CLASS.WARN, v)
})

test('E68R26 allow classification', () => {
  for (const v of E68R26_ALLOW) assert.equal(E68R26Classify(v), E68R26_CLASS.ALLOW, v)
})

test('E68R26 unknown classification', () => {
  assert.equal(E68R26Classify('zzz-not-in-any-e68-catalog-77'), E68R26_CLASS.UNKNOWN)
})
