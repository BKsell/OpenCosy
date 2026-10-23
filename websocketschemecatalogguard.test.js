'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WSPClassify, WSP_CLASS, WSP_BLOCK, WSP_WARN, WSP_ALLOW } = require('./websocketschemecatalogguard.js')

test('WSP block classification', () => {
  for (const v of WSP_BLOCK) assert.equal(WSPClassify(v), WSP_CLASS.BLOCK, v)
})

test('WSP warn classification', () => {
  for (const v of WSP_WARN) assert.equal(WSPClassify(v), WSP_CLASS.WARN, v)
})

test('WSP allow classification', () => {
  for (const v of WSP_ALLOW) assert.equal(WSPClassify(v), WSP_CLASS.ALLOW, v)
})

test('WSP unknown classification', () => {
  assert.equal(WSPClassify('zzz-not-in-catalog-7'), WSP_CLASS.UNKNOWN)
})
