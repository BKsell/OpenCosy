'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T47Classify, E70T47_CLASS, E70T47_BLOCK, E70T47_WARN, E70T47_ALLOW } = require('./e70geometricshapescatalogguard.js')

test('E70T47 block classification', () => {
  for (const v of E70T47_BLOCK) assert.equal(E70T47Classify(v), E70T47_CLASS.BLOCK, v)
})

test('E70T47 warn classification', () => {
  for (const v of E70T47_WARN) assert.equal(E70T47Classify(v), E70T47_CLASS.WARN, v)
})

test('E70T47 allow classification', () => {
  for (const v of E70T47_ALLOW) assert.equal(E70T47Classify(v), E70T47_CLASS.ALLOW, v)
})

test('E70T47 unknown classification', () => {
  assert.equal(E70T47Classify('zzz-not-in-any-e70-catalog-99'), E70T47_CLASS.UNKNOWN)
})
