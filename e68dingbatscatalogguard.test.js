'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R35Classify, E68R35_CLASS, E68R35_BLOCK, E68R35_WARN, E68R35_ALLOW } = require('./e68dingbatscatalogguard.js')

test('E68R35 block classification', () => {
  for (const v of E68R35_BLOCK) assert.equal(E68R35Classify(v), E68R35_CLASS.BLOCK, v)
})

test('E68R35 warn classification', () => {
  for (const v of E68R35_WARN) assert.equal(E68R35Classify(v), E68R35_CLASS.WARN, v)
})

test('E68R35 allow classification', () => {
  for (const v of E68R35_ALLOW) assert.equal(E68R35Classify(v), E68R35_CLASS.ALLOW, v)
})

test('E68R35 unknown classification', () => {
  assert.equal(E68R35Classify('zzz-not-in-any-e68-catalog-77'), E68R35_CLASS.UNKNOWN)
})
