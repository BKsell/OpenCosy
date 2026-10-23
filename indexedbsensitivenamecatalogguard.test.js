'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IDSClassify, IDS_CLASS, IDS_BLOCK, IDS_WARN, IDS_ALLOW } = require('./indexedbsensitivenamecatalogguard.js')

test('IDS block classification', () => {
  for (const v of IDS_BLOCK) assert.equal(IDSClassify(v), IDS_CLASS.BLOCK, v)
})

test('IDS warn classification', () => {
  for (const v of IDS_WARN) assert.equal(IDSClassify(v), IDS_CLASS.WARN, v)
})

test('IDS allow classification', () => {
  for (const v of IDS_ALLOW) assert.equal(IDSClassify(v), IDS_CLASS.ALLOW, v)
})

test('IDS unknown classification', () => {
  assert.equal(IDSClassify('zzz-not-in-catalog-7'), IDS_CLASS.UNKNOWN)
})
