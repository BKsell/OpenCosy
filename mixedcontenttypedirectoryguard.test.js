'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MCTClassify, MCT_CLASS, MCT_BLOCK, MCT_WARN, MCT_ALLOW } = require('./mixedcontenttypedirectoryguard.js')

test('MCT block classification', () => {
  for (const v of MCT_BLOCK) assert.equal(MCTClassify(v), MCT_CLASS.BLOCK, v)
})

test('MCT warn classification', () => {
  for (const v of MCT_WARN) assert.equal(MCTClassify(v), MCT_CLASS.WARN, v)
})

test('MCT allow classification', () => {
  for (const v of MCT_ALLOW) assert.equal(MCTClassify(v), MCT_CLASS.ALLOW, v)
})

test('MCT unknown classification', () => {
  assert.equal(MCTClassify('zzz-not-in-catalog-7'), MCT_CLASS.UNKNOWN)
})
