'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R27Classify, E68R27_CLASS, E68R27_BLOCK, E68R27_WARN, E68R27_ALLOW } = require('./e68mathoperatorscatalogguard.js')

test('E68R27 block classification', () => {
  for (const v of E68R27_BLOCK) assert.equal(E68R27Classify(v), E68R27_CLASS.BLOCK, v)
})

test('E68R27 warn classification', () => {
  for (const v of E68R27_WARN) assert.equal(E68R27Classify(v), E68R27_CLASS.WARN, v)
})

test('E68R27 allow classification', () => {
  for (const v of E68R27_ALLOW) assert.equal(E68R27Classify(v), E68R27_CLASS.ALLOW, v)
})

test('E68R27 unknown classification', () => {
  assert.equal(E68R27Classify('zzz-not-in-any-e68-catalog-77'), E68R27_CLASS.UNKNOWN)
})
