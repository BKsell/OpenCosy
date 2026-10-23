'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CSKClassify, CSK_CLASS, CSK_BLOCK, CSK_WARN, CSK_ALLOW } = require('./cspkeywordcatalogguard.js')

test('CSK block classification', () => {
  for (const v of CSK_BLOCK) assert.equal(CSKClassify(v), CSK_CLASS.BLOCK, v)
})

test('CSK warn classification', () => {
  for (const v of CSK_WARN) assert.equal(CSKClassify(v), CSK_CLASS.WARN, v)
})

test('CSK allow classification', () => {
  for (const v of CSK_ALLOW) assert.equal(CSKClassify(v), CSK_CLASS.ALLOW, v)
})

test('CSK unknown classification', () => {
  assert.equal(CSKClassify('zzz-not-in-catalog-7'), CSK_CLASS.UNKNOWN)
})
