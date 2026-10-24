'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R30Classify, E68R30_CLASS, E68R30_BLOCK, E68R30_WARN, E68R30_ALLOW } = require('./e68enclosedcatalogguard.js')

test('E68R30 block classification', () => {
  for (const v of E68R30_BLOCK) assert.equal(E68R30Classify(v), E68R30_CLASS.BLOCK, v)
})

test('E68R30 warn classification', () => {
  for (const v of E68R30_WARN) assert.equal(E68R30Classify(v), E68R30_CLASS.WARN, v)
})

test('E68R30 allow classification', () => {
  for (const v of E68R30_ALLOW) assert.equal(E68R30Classify(v), E68R30_CLASS.ALLOW, v)
})

test('E68R30 unknown classification', () => {
  assert.equal(E68R30Classify('zzz-not-in-any-e68-catalog-77'), E68R30_CLASS.UNKNOWN)
})
