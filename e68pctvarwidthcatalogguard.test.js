'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68PVWClassify, E68PVW_CLASS, E68PVW_BLOCK, E68PVW_WARN, E68PVW_ALLOW } = require('./e68pctvarwidthcatalogguard.js')

test('E68PVW block classification', () => {
  for (const v of E68PVW_BLOCK) assert.equal(E68PVWClassify(v), E68PVW_CLASS.BLOCK, v)
})

test('E68PVW warn classification', () => {
  for (const v of E68PVW_WARN) assert.equal(E68PVWClassify(v), E68PVW_CLASS.WARN, v)
})

test('E68PVW allow classification', () => {
  for (const v of E68PVW_ALLOW) assert.equal(E68PVWClassify(v), E68PVW_CLASS.ALLOW, v)
})

test('E68PVW unknown classification', () => {
  assert.equal(E68PVWClassify('zzz-not-in-any-e68-catalog-77'), E68PVW_CLASS.UNKNOWN)
})
