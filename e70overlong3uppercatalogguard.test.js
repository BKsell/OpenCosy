'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70O3UClassify, E70O3U_CLASS, E70O3U_BLOCK, E70O3U_WARN, E70O3U_ALLOW } = require('./e70overlong3uppercatalogguard.js')

test('E70O3U block classification', () => {
  for (const v of E70O3U_BLOCK) assert.equal(E70O3UClassify(v), E70O3U_CLASS.BLOCK, v)
})

test('E70O3U warn classification', () => {
  for (const v of E70O3U_WARN) assert.equal(E70O3UClassify(v), E70O3U_CLASS.WARN, v)
})

test('E70O3U allow classification', () => {
  for (const v of E70O3U_ALLOW) assert.equal(E70O3UClassify(v), E70O3U_CLASS.ALLOW, v)
})

test('E70O3U unknown classification', () => {
  assert.equal(E70O3UClassify('zzz-not-in-any-e70-catalog-99'), E70O3U_CLASS.UNKNOWN)
})
