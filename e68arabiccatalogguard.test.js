'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R02Classify, E68R02_CLASS, E68R02_BLOCK, E68R02_WARN, E68R02_ALLOW } = require('./e68arabiccatalogguard.js')

test('E68R02 block classification', () => {
  for (const v of E68R02_BLOCK) assert.equal(E68R02Classify(v), E68R02_CLASS.BLOCK, v)
})

test('E68R02 warn classification', () => {
  for (const v of E68R02_WARN) assert.equal(E68R02Classify(v), E68R02_CLASS.WARN, v)
})

test('E68R02 allow classification', () => {
  for (const v of E68R02_ALLOW) assert.equal(E68R02Classify(v), E68R02_CLASS.ALLOW, v)
})

test('E68R02 unknown classification', () => {
  assert.equal(E68R02Classify('zzz-not-in-any-e68-catalog-77'), E68R02_CLASS.UNKNOWN)
})
