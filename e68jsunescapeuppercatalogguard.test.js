'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68JUUClassify, E68JUU_CLASS, E68JUU_BLOCK, E68JUU_WARN, E68JUU_ALLOW } = require('./e68jsunescapeuppercatalogguard.js')

test('E68JUU block classification', () => {
  for (const v of E68JUU_BLOCK) assert.equal(E68JUUClassify(v), E68JUU_CLASS.BLOCK, v)
})

test('E68JUU warn classification', () => {
  for (const v of E68JUU_WARN) assert.equal(E68JUUClassify(v), E68JUU_CLASS.WARN, v)
})

test('E68JUU allow classification', () => {
  for (const v of E68JUU_ALLOW) assert.equal(E68JUUClassify(v), E68JUU_CLASS.ALLOW, v)
})

test('E68JUU unknown classification', () => {
  assert.equal(E68JUUClassify('zzz-not-in-any-e68-catalog-77'), E68JUU_CLASS.UNKNOWN)
})
