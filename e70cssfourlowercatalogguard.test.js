'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70C4LClassify, E70C4L_CLASS, E70C4L_BLOCK, E70C4L_WARN, E70C4L_ALLOW } = require('./e70cssfourlowercatalogguard.js')

test('E70C4L block classification', () => {
  for (const v of E70C4L_BLOCK) assert.equal(E70C4LClassify(v), E70C4L_CLASS.BLOCK, v)
})

test('E70C4L warn classification', () => {
  for (const v of E70C4L_WARN) assert.equal(E70C4LClassify(v), E70C4L_CLASS.WARN, v)
})

test('E70C4L allow classification', () => {
  for (const v of E70C4L_ALLOW) assert.equal(E70C4LClassify(v), E70C4L_CLASS.ALLOW, v)
})

test('E70C4L unknown classification', () => {
  assert.equal(E70C4LClassify('zzz-not-in-any-e70-catalog-99'), E70C4L_CLASS.UNKNOWN)
})
