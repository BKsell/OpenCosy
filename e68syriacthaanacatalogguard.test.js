'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R03Classify, E68R03_CLASS, E68R03_BLOCK, E68R03_WARN, E68R03_ALLOW } = require('./e68syriacthaanacatalogguard.js')

test('E68R03 block classification', () => {
  for (const v of E68R03_BLOCK) assert.equal(E68R03Classify(v), E68R03_CLASS.BLOCK, v)
})

test('E68R03 warn classification', () => {
  for (const v of E68R03_WARN) assert.equal(E68R03Classify(v), E68R03_CLASS.WARN, v)
})

test('E68R03 allow classification', () => {
  for (const v of E68R03_ALLOW) assert.equal(E68R03Classify(v), E68R03_CLASS.ALLOW, v)
})

test('E68R03 unknown classification', () => {
  assert.equal(E68R03Classify('zzz-not-in-any-e68-catalog-77'), E68R03_CLASS.UNKNOWN)
})
