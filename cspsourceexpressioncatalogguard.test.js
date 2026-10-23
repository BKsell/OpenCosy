'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CSEClassify, CSE_CLASS, CSE_BLOCK, CSE_WARN, CSE_ALLOW } = require('./cspsourceexpressioncatalogguard.js')

test('CSE block classification', () => {
  for (const v of CSE_BLOCK) assert.equal(CSEClassify(v), CSE_CLASS.BLOCK, v)
})

test('CSE warn classification', () => {
  for (const v of CSE_WARN) assert.equal(CSEClassify(v), CSE_CLASS.WARN, v)
})

test('CSE allow classification', () => {
  for (const v of CSE_ALLOW) assert.equal(CSEClassify(v), CSE_CLASS.ALLOW, v)
})

test('CSE unknown classification', () => {
  assert.equal(CSEClassify('zzz-not-in-catalog-7'), CSE_CLASS.UNKNOWN)
})
