'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R06Classify, E68R06_CLASS, E68R06_BLOCK, E68R06_WARN, E68R06_ALLOW } = require('./e68bengalicatalogguard.js')

test('E68R06 block classification', () => {
  for (const v of E68R06_BLOCK) assert.equal(E68R06Classify(v), E68R06_CLASS.BLOCK, v)
})

test('E68R06 warn classification', () => {
  for (const v of E68R06_WARN) assert.equal(E68R06Classify(v), E68R06_CLASS.WARN, v)
})

test('E68R06 allow classification', () => {
  for (const v of E68R06_ALLOW) assert.equal(E68R06Classify(v), E68R06_CLASS.ALLOW, v)
})

test('E68R06 unknown classification', () => {
  assert.equal(E68R06Classify('zzz-not-in-any-e68-catalog-77'), E68R06_CLASS.UNKNOWN)
})
