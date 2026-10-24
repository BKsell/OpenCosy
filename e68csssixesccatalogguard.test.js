'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68CSSClassify, E68CSS_CLASS, E68CSS_BLOCK, E68CSS_WARN, E68CSS_ALLOW } = require('./e68csssixesccatalogguard.js')

test('E68CSS block classification', () => {
  for (const v of E68CSS_BLOCK) assert.equal(E68CSSClassify(v), E68CSS_CLASS.BLOCK, v)
})

test('E68CSS warn classification', () => {
  for (const v of E68CSS_WARN) assert.equal(E68CSSClassify(v), E68CSS_CLASS.WARN, v)
})

test('E68CSS allow classification', () => {
  for (const v of E68CSS_ALLOW) assert.equal(E68CSSClassify(v), E68CSS_CLASS.ALLOW, v)
})

test('E68CSS unknown classification', () => {
  assert.equal(E68CSSClassify('zzz-not-in-any-e68-catalog-77'), E68CSS_CLASS.UNKNOWN)
})
