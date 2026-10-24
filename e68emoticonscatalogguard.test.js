'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68S01Classify, E68S01_CLASS, E68S01_BLOCK, E68S01_WARN, E68S01_ALLOW } = require('./e68emoticonscatalogguard.js')

test('E68S01 block classification', () => {
  for (const v of E68S01_BLOCK) assert.equal(E68S01Classify(v), E68S01_CLASS.BLOCK, v)
})

test('E68S01 warn classification', () => {
  for (const v of E68S01_WARN) assert.equal(E68S01Classify(v), E68S01_CLASS.WARN, v)
})

test('E68S01 allow classification', () => {
  for (const v of E68S01_ALLOW) assert.equal(E68S01Classify(v), E68S01_CLASS.ALLOW, v)
})

test('E68S01 unknown classification', () => {
  assert.equal(E68S01Classify('zzz-not-in-any-e68-catalog-77'), E68S01_CLASS.UNKNOWN)
})
