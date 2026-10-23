'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CSSClassify, CSS_CLASS, CSS_BLOCK, CSS_WARN, CSS_ALLOW } = require('./csspropertydirectoryguard.js')

test('CSS block classification', () => {
  for (const v of CSS_BLOCK) assert.equal(CSSClassify(v), CSS_CLASS.BLOCK, v)
})

test('CSS warn classification', () => {
  for (const v of CSS_WARN) assert.equal(CSSClassify(v), CSS_CLASS.WARN, v)
})

test('CSS allow classification', () => {
  for (const v of CSS_ALLOW) assert.equal(CSSClassify(v), CSS_CLASS.ALLOW, v)
})

test('CSS unknown classification', () => {
  assert.equal(CSSClassify('zzz-not-in-catalog-7'), CSS_CLASS.UNKNOWN)
})
