'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R34Classify, E68R34_CLASS, E68R34_BLOCK, E68R34_WARN, E68R34_ALLOW } = require('./e68miscsymbolscatalogguard.js')

test('E68R34 block classification', () => {
  for (const v of E68R34_BLOCK) assert.equal(E68R34Classify(v), E68R34_CLASS.BLOCK, v)
})

test('E68R34 warn classification', () => {
  for (const v of E68R34_WARN) assert.equal(E68R34Classify(v), E68R34_CLASS.WARN, v)
})

test('E68R34 allow classification', () => {
  for (const v of E68R34_ALLOW) assert.equal(E68R34Classify(v), E68R34_CLASS.ALLOW, v)
})

test('E68R34 unknown classification', () => {
  assert.equal(E68R34Classify('zzz-not-in-any-e68-catalog-77'), E68R34_CLASS.UNKNOWN)
})
