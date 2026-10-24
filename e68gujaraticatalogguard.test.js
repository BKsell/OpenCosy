'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R08Classify, E68R08_CLASS, E68R08_BLOCK, E68R08_WARN, E68R08_ALLOW } = require('./e68gujaraticatalogguard.js')

test('E68R08 block classification', () => {
  for (const v of E68R08_BLOCK) assert.equal(E68R08Classify(v), E68R08_CLASS.BLOCK, v)
})

test('E68R08 warn classification', () => {
  for (const v of E68R08_WARN) assert.equal(E68R08Classify(v), E68R08_CLASS.WARN, v)
})

test('E68R08 allow classification', () => {
  for (const v of E68R08_ALLOW) assert.equal(E68R08Classify(v), E68R08_CLASS.ALLOW, v)
})

test('E68R08 unknown classification', () => {
  assert.equal(E68R08Classify('zzz-not-in-any-e68-catalog-77'), E68R08_CLASS.UNKNOWN)
})
