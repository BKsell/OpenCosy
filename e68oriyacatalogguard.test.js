'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R09Classify, E68R09_CLASS, E68R09_BLOCK, E68R09_WARN, E68R09_ALLOW } = require('./e68oriyacatalogguard.js')

test('E68R09 block classification', () => {
  for (const v of E68R09_BLOCK) assert.equal(E68R09Classify(v), E68R09_CLASS.BLOCK, v)
})

test('E68R09 warn classification', () => {
  for (const v of E68R09_WARN) assert.equal(E68R09Classify(v), E68R09_CLASS.WARN, v)
})

test('E68R09 allow classification', () => {
  for (const v of E68R09_ALLOW) assert.equal(E68R09Classify(v), E68R09_CLASS.ALLOW, v)
})

test('E68R09 unknown classification', () => {
  assert.equal(E68R09Classify('zzz-not-in-any-e68-catalog-77'), E68R09_CLASS.UNKNOWN)
})
