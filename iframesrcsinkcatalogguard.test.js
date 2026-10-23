'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { IFSClassify, IFS_CLASS, IFS_BLOCK, IFS_WARN, IFS_ALLOW } = require('./iframesrcsinkcatalogguard.js')

test('IFS block classification', () => {
  for (const v of IFS_BLOCK) assert.equal(IFSClassify(v), IFS_CLASS.BLOCK, v)
})

test('IFS warn classification', () => {
  for (const v of IFS_WARN) assert.equal(IFSClassify(v), IFS_CLASS.WARN, v)
})

test('IFS allow classification', () => {
  for (const v of IFS_ALLOW) assert.equal(IFSClassify(v), IFS_CLASS.ALLOW, v)
})

test('IFS unknown classification', () => {
  assert.equal(IFSClassify('zzz-not-in-catalog-7'), IFS_CLASS.UNKNOWN)
})
