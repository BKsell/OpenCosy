'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CKWClassify, CKW_CLASS, CKW_BLOCK, CKW_WARN, CKW_ALLOW } = require('./documentcookiewritecatalogguard.js')

test('CKW block classification', () => {
  for (const v of CKW_BLOCK) assert.equal(CKWClassify(v), CKW_CLASS.BLOCK, v)
})

test('CKW warn classification', () => {
  for (const v of CKW_WARN) assert.equal(CKWClassify(v), CKW_CLASS.WARN, v)
})

test('CKW allow classification', () => {
  for (const v of CKW_ALLOW) assert.equal(CKWClassify(v), CKW_CLASS.ALLOW, v)
})

test('CKW unknown classification', () => {
  assert.equal(CKWClassify('zzz-not-in-catalog-7'), CKW_CLASS.UNKNOWN)
})
