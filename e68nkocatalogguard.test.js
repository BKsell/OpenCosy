'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R04Classify, E68R04_CLASS, E68R04_BLOCK, E68R04_WARN, E68R04_ALLOW } = require('./e68nkocatalogguard.js')

test('E68R04 block classification', () => {
  for (const v of E68R04_BLOCK) assert.equal(E68R04Classify(v), E68R04_CLASS.BLOCK, v)
})

test('E68R04 warn classification', () => {
  for (const v of E68R04_WARN) assert.equal(E68R04Classify(v), E68R04_CLASS.WARN, v)
})

test('E68R04 allow classification', () => {
  for (const v of E68R04_ALLOW) assert.equal(E68R04Classify(v), E68R04_CLASS.ALLOW, v)
})

test('E68R04 unknown classification', () => {
  assert.equal(E68R04Classify('zzz-not-in-any-e68-catalog-77'), E68R04_CLASS.UNKNOWN)
})
