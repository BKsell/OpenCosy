'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { STNClassify, STN_CLASS, STN_BLOCK, STN_WARN, STN_ALLOW } = require('./storagesensitivenamecatalogguard.js')

test('STN block classification', () => {
  for (const v of STN_BLOCK) assert.equal(STNClassify(v), STN_CLASS.BLOCK, v)
})

test('STN warn classification', () => {
  for (const v of STN_WARN) assert.equal(STNClassify(v), STN_CLASS.WARN, v)
})

test('STN allow classification', () => {
  for (const v of STN_ALLOW) assert.equal(STNClassify(v), STN_CLASS.ALLOW, v)
})

test('STN unknown classification', () => {
  assert.equal(STNClassify('zzz-not-in-catalog-7'), STN_CLASS.UNKNOWN)
})
