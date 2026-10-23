'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XHRClassify, XHR_CLASS, XHR_BLOCK, XHR_WARN, XHR_ALLOW } = require('./xhrcrosscookiecatalogguard.js')

test('XHR block classification', () => {
  for (const v of XHR_BLOCK) assert.equal(XHRClassify(v), XHR_CLASS.BLOCK, v)
})

test('XHR warn classification', () => {
  for (const v of XHR_WARN) assert.equal(XHRClassify(v), XHR_CLASS.WARN, v)
})

test('XHR allow classification', () => {
  for (const v of XHR_ALLOW) assert.equal(XHRClassify(v), XHR_CLASS.ALLOW, v)
})

test('XHR unknown classification', () => {
  assert.equal(XHRClassify('zzz-not-in-catalog-7'), XHR_CLASS.UNKNOWN)
})
