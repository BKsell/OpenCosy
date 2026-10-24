'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68S00Classify, E68S00_CLASS, E68S00_BLOCK, E68S00_WARN, E68S00_ALLOW } = require('./e68emojisympictographscatalogguard.js')

test('E68S00 block classification', () => {
  for (const v of E68S00_BLOCK) assert.equal(E68S00Classify(v), E68S00_CLASS.BLOCK, v)
})

test('E68S00 warn classification', () => {
  for (const v of E68S00_WARN) assert.equal(E68S00Classify(v), E68S00_CLASS.WARN, v)
})

test('E68S00 allow classification', () => {
  for (const v of E68S00_ALLOW) assert.equal(E68S00Classify(v), E68S00_CLASS.ALLOW, v)
})

test('E68S00 unknown classification', () => {
  assert.equal(E68S00Classify('zzz-not-in-any-e68-catalog-77'), E68S00_CLASS.UNKNOWN)
})
