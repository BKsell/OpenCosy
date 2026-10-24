'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R18Classify, E68R18_CLASS, E68R18_BLOCK, E68R18_WARN, E68R18_ALLOW } = require('./e68myanmarcatalogguard.js')

test('E68R18 block classification', () => {
  for (const v of E68R18_BLOCK) assert.equal(E68R18Classify(v), E68R18_CLASS.BLOCK, v)
})

test('E68R18 warn classification', () => {
  for (const v of E68R18_WARN) assert.equal(E68R18Classify(v), E68R18_CLASS.WARN, v)
})

test('E68R18 allow classification', () => {
  for (const v of E68R18_ALLOW) assert.equal(E68R18Classify(v), E68R18_CLASS.ALLOW, v)
})

test('E68R18 unknown classification', () => {
  assert.equal(E68R18Classify('zzz-not-in-any-e68-catalog-77'), E68R18_CLASS.UNKNOWN)
})
