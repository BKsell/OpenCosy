'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68O03Classify, E68O03_CLASS, E68O03_BLOCK, E68O03_WARN, E68O03_ALLOW } = require('./e68oct0olowercatalogguard.js')

test('E68O03 block classification', () => {
  for (const v of E68O03_BLOCK) assert.equal(E68O03Classify(v), E68O03_CLASS.BLOCK, v)
})

test('E68O03 warn classification', () => {
  for (const v of E68O03_WARN) assert.equal(E68O03Classify(v), E68O03_CLASS.WARN, v)
})

test('E68O03 allow classification', () => {
  for (const v of E68O03_ALLOW) assert.equal(E68O03Classify(v), E68O03_CLASS.ALLOW, v)
})

test('E68O03 unknown classification', () => {
  assert.equal(E68O03Classify('zzz-not-in-any-e68-catalog-77'), E68O03_CLASS.UNKNOWN)
})
