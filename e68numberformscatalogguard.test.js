'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R25Classify, E68R25_CLASS, E68R25_BLOCK, E68R25_WARN, E68R25_ALLOW } = require('./e68numberformscatalogguard.js')

test('E68R25 block classification', () => {
  for (const v of E68R25_BLOCK) assert.equal(E68R25Classify(v), E68R25_CLASS.BLOCK, v)
})

test('E68R25 warn classification', () => {
  for (const v of E68R25_WARN) assert.equal(E68R25Classify(v), E68R25_CLASS.WARN, v)
})

test('E68R25 allow classification', () => {
  for (const v of E68R25_ALLOW) assert.equal(E68R25Classify(v), E68R25_CLASS.ALLOW, v)
})

test('E68R25 unknown classification', () => {
  assert.equal(E68R25Classify('zzz-not-in-any-e68-catalog-77'), E68R25_CLASS.UNKNOWN)
})
