'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XSJClassify, XSJ_CLASS, XSJ_BLOCK, XSJ_WARN, XSJ_ALLOW } = require('./xsltprocessorsinkcatalogguard.js')

test('XSJ block classification', () => {
  for (const v of XSJ_BLOCK) assert.equal(XSJClassify(v), XSJ_CLASS.BLOCK, v)
})

test('XSJ warn classification', () => {
  for (const v of XSJ_WARN) assert.equal(XSJClassify(v), XSJ_CLASS.WARN, v)
})

test('XSJ allow classification', () => {
  for (const v of XSJ_ALLOW) assert.equal(XSJClassify(v), XSJ_CLASS.ALLOW, v)
})

test('XSJ unknown classification', () => {
  assert.equal(XSJClassify('zzz-not-in-catalog-7'), XSJ_CLASS.UNKNOWN)
})
