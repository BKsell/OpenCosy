'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { BCNClassify, BCN_CLASS, BCN_BLOCK, BCN_WARN, BCN_ALLOW } = require('./sendbeaconthirdpartycatalogguard.js')

test('BCN block classification', () => {
  for (const v of BCN_BLOCK) assert.equal(BCNClassify(v), BCN_CLASS.BLOCK, v)
})

test('BCN warn classification', () => {
  for (const v of BCN_WARN) assert.equal(BCNClassify(v), BCN_CLASS.WARN, v)
})

test('BCN allow classification', () => {
  for (const v of BCN_ALLOW) assert.equal(BCNClassify(v), BCN_CLASS.ALLOW, v)
})

test('BCN unknown classification', () => {
  assert.equal(BCNClassify('zzz-not-in-catalog-7'), BCN_CLASS.UNKNOWN)
})
