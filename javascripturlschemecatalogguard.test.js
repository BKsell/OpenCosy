'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { JSUClassify, JSU_CLASS, JSU_BLOCK, JSU_WARN, JSU_ALLOW } = require('./javascripturlschemecatalogguard.js')

test('JSU block classification', () => {
  for (const v of JSU_BLOCK) assert.equal(JSUClassify(v), JSU_CLASS.BLOCK, v)
})

test('JSU warn classification', () => {
  for (const v of JSU_WARN) assert.equal(JSUClassify(v), JSU_CLASS.WARN, v)
})

test('JSU allow classification', () => {
  for (const v of JSU_ALLOW) assert.equal(JSUClassify(v), JSU_CLASS.ALLOW, v)
})

test('JSU unknown classification', () => {
  assert.equal(JSUClassify('zzz-not-in-catalog-7'), JSU_CLASS.UNKNOWN)
})
