'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68PCDClassify, E68PCD_CLASS, E68PCD_BLOCK, E68PCD_WARN, E68PCD_ALLOW } = require('./e68pythonchrcatalogguard.js')

test('E68PCD block classification', () => {
  for (const v of E68PCD_BLOCK) assert.equal(E68PCDClassify(v), E68PCD_CLASS.BLOCK, v)
})

test('E68PCD warn classification', () => {
  for (const v of E68PCD_WARN) assert.equal(E68PCDClassify(v), E68PCD_CLASS.WARN, v)
})

test('E68PCD allow classification', () => {
  for (const v of E68PCD_ALLOW) assert.equal(E68PCDClassify(v), E68PCD_CLASS.ALLOW, v)
})

test('E68PCD unknown classification', () => {
  assert.equal(E68PCDClassify('zzz-not-in-any-e68-catalog-77'), E68PCD_CLASS.UNKNOWN)
})
