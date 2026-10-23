'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HADClassify, HAD_CLASS, HAD_BLOCK, HAD_WARN, HAD_ALLOW } = require('./htmlattributedirectoryguard.js')

test('HAD block classification', () => {
  for (const v of HAD_BLOCK) assert.equal(HADClassify(v), HAD_CLASS.BLOCK, v)
})

test('HAD warn classification', () => {
  for (const v of HAD_WARN) assert.equal(HADClassify(v), HAD_CLASS.WARN, v)
})

test('HAD allow classification', () => {
  for (const v of HAD_ALLOW) assert.equal(HADClassify(v), HAD_CLASS.ALLOW, v)
})

test('HAD unknown classification', () => {
  assert.equal(HADClassify('zzz-not-in-catalog-7'), HAD_CLASS.UNKNOWN)
})
