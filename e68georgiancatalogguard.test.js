'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68R19Classify, E68R19_CLASS, E68R19_BLOCK, E68R19_WARN, E68R19_ALLOW } = require('./e68georgiancatalogguard.js')

test('E68R19 block classification', () => {
  for (const v of E68R19_BLOCK) assert.equal(E68R19Classify(v), E68R19_CLASS.BLOCK, v)
})

test('E68R19 warn classification', () => {
  for (const v of E68R19_WARN) assert.equal(E68R19Classify(v), E68R19_CLASS.WARN, v)
})

test('E68R19 allow classification', () => {
  for (const v of E68R19_ALLOW) assert.equal(E68R19Classify(v), E68R19_CLASS.ALLOW, v)
})

test('E68R19 unknown classification', () => {
  assert.equal(E68R19Classify('zzz-not-in-any-e68-catalog-77'), E68R19_CLASS.UNKNOWN)
})
