'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70O3LClassify, E70O3L_CLASS, E70O3L_BLOCK, E70O3L_WARN, E70O3L_ALLOW } = require('./e70overlong3lowercatalogguard.js')

test('E70O3L block classification', () => {
  for (const v of E70O3L_BLOCK) assert.equal(E70O3LClassify(v), E70O3L_CLASS.BLOCK, v)
})

test('E70O3L warn classification', () => {
  for (const v of E70O3L_WARN) assert.equal(E70O3LClassify(v), E70O3L_CLASS.WARN, v)
})

test('E70O3L allow classification', () => {
  for (const v of E70O3L_ALLOW) assert.equal(E70O3LClassify(v), E70O3L_CLASS.ALLOW, v)
})

test('E70O3L unknown classification', () => {
  assert.equal(E70O3LClassify('zzz-not-in-any-e70-catalog-99'), E70O3L_CLASS.UNKNOWN)
})
